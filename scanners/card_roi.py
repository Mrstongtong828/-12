"""
卡面 ROI 检测与透视矫正。

在 ocr_worker._ocr_once 中于 PaddleOCR 调用前插入,针对 BLOB 图片中的
身份证 / 银行卡 / 户籍页做"检测四边形 → 透视矫正 → 归一化画布"预处理,
让 PaddleOCR 看到的是"卡片填满画面"的清晰图,提升字符识别准确率。

设计原则:
  1. 任何失败路径返回 (原图, "passthrough"),决不返回 None,决不抛异常。
     调用方(ocr_worker)无需做 None 判断。
  2. 顶层只 import stdlib;cv2/numpy 按 _decode_image 的风格 lazy-import,
     环境缺 cv2 / OpenCV 运行时异常 → 自动 passthrough。
  3. 不引入 paddle / 项目深层模块:`python -c "import scanners.card_roi"` 秒过。
"""
from __future__ import annotations

from typing import Optional, Tuple


# 宽高比分类阈值
# 身份证 / 银行卡真实长宽比 ≈ 85.6/54 = 1.585,给 ±10% 容差
LANDSCAPE_AR_LO = 1.45
LANDSCAPE_AR_HI = 1.75
# 竖向户籍页 / 文档页,通常长宽比 ≈ 1/1.4 ≈ 0.71(A4 竖向更接近 0.707)
PORTRAIT_AR_LO = 0.55
PORTRAIT_AR_HI = 0.75

# 面积过滤:<0.15 判为 logo/噪声,>0.92 判为图本身已是裁好的卡(warp 会破坏)
MIN_AREA_RATIO = 0.15
MAX_AREA_RATIO = 0.92

# 归一化 canvas(长边受 max_long_edge 钳制)
LANDSCAPE_CANVAS = (1012, 640)   # (W, H) 比例 ≈ 1.58
PORTRAIT_CANVAS = (720, 1012)    # (W, H) 比例 ≈ 0.71


def _order_corners(pts):
    """按 TL/TR/BR/BL 顺序排列四点。使用 sum/diff 经典技巧。"""
    import numpy as np
    pts = pts.reshape(4, 2).astype("float32")
    s = pts.sum(axis=1)
    d = np.diff(pts, axis=1).reshape(-1)
    ordered = np.zeros((4, 2), dtype="float32")
    ordered[0] = pts[np.argmin(s)]   # TL: x+y 最小
    ordered[2] = pts[np.argmax(s)]   # BR: x+y 最大
    ordered[1] = pts[np.argmin(d)]   # TR: y-x 最小
    ordered[3] = pts[np.argmax(d)]   # BL: y-x 最大
    return ordered


def _find_card_quad(gray, cv2) -> Optional[object]:
    """在灰度图上找"最大合格四边形"。返回 ordered 4x2 ndarray 或 None。"""
    import numpy as np
    h, w = gray.shape[:2]
    total_area = float(h * w)

    # 双边滤波保边去噪,比高斯 + 再调 Canny 稳
    blurred = cv2.bilateralFilter(gray, d=7, sigmaColor=50, sigmaSpace=50)
    edged = cv2.Canny(blurred, 50, 150)
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    edged = cv2.dilate(edged, kernel, iterations=1)

    # RETR_EXTERNAL 只要最外层轮廓;按面积降序取前 5
    contours, _ = cv2.findContours(edged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None
    contours = sorted(contours, key=cv2.contourArea, reverse=True)[:5]

    for c in contours:
        area = cv2.contourArea(c)
        if area < MIN_AREA_RATIO * total_area:
            break
        if area > MAX_AREA_RATIO * total_area:
            # 图本身就是裁好的卡,warp 会破坏 — 跳过这个候选继续试更小的
            continue
        peri = cv2.arcLength(c, True)
        approx = cv2.approxPolyDP(c, 0.02 * peri, True)
        if len(approx) != 4:
            continue
        if not cv2.isContourConvex(approx):
            continue
        return _order_corners(approx)
    return None


def _classify_and_canvas(quad) -> Optional[Tuple[str, Tuple[int, int]]]:
    """依据四边形宽高比决定 canvas。命中横/竖带之一返回 (tag, (W,H)),否则 None。"""
    import numpy as np
    tl, tr, br, bl = quad
    wA = np.linalg.norm(br - bl)
    wB = np.linalg.norm(tr - tl)
    hA = np.linalg.norm(tr - br)
    hB = np.linalg.norm(tl - bl)
    quad_w = (wA + wB) / 2.0
    quad_h = (hA + hB) / 2.0
    if quad_w <= 1 or quad_h <= 1:
        return None
    ar = quad_w / quad_h
    if LANDSCAPE_AR_LO <= ar <= LANDSCAPE_AR_HI:
        return "landscape", LANDSCAPE_CANVAS
    if PORTRAIT_AR_LO <= ar <= PORTRAIT_AR_HI:
        return "portrait", PORTRAIT_CANVAS
    return None


def _clamp_canvas(canvas_wh: Tuple[int, int], max_long_edge: int) -> Tuple[int, int]:
    """若 canvas 长边 > max_long_edge,等比缩到上限。"""
    w, h = canvas_wh
    long_edge = max(w, h)
    if long_edge <= max_long_edge:
        return w, h
    scale = max_long_edge / float(long_edge)
    return max(1, int(w * scale)), max(1, int(h * scale))


def detect_and_warp(img, *, max_long_edge: int = 1100) -> Tuple[object, str]:
    """
    卡面检测 + 透视矫正。

    参数:
      img            - _decode_image 的输出,np.ndarray BGR uint8,HxWx3。
                       长边已 ≤ MAX_OCR_SIDE(ocr_worker.py 中当前为 800)。
      max_long_edge  - 矫正后 canvas 长边上限,默认 1100。

    返回:
      (输出图, tag):tag ∈ {"warped", "passthrough"}。
    """
    # 任何分支异常都 passthrough,绝不抛给上游
    try:
        import numpy as np
        import cv2
    except Exception:
        return img, "passthrough"

    try:
        if img is None or getattr(img, "ndim", 0) < 2:
            return img, "passthrough"
        h, w = img.shape[:2]
        # 极小图直接放过 — 没法做可靠的轮廓检测
        if min(h, w) < 80:
            return img, "passthrough"

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
        quad = _find_card_quad(gray, cv2)
        if quad is None:
            return img, "passthrough"

        cls = _classify_and_canvas(quad)
        if cls is None:
            return img, "passthrough"
        _tag_name, canvas_wh = cls
        canvas_w, canvas_h = _clamp_canvas(canvas_wh, max_long_edge)

        dst = np.array([
            [0, 0],
            [canvas_w - 1, 0],
            [canvas_w - 1, canvas_h - 1],
            [0, canvas_h - 1],
        ], dtype="float32")
        M = cv2.getPerspectiveTransform(quad, dst)
        warped = cv2.warpPerspective(img, M, (canvas_w, canvas_h), flags=cv2.INTER_CUBIC)
        return warped, "warped"
    except Exception:
        return img, "passthrough"
