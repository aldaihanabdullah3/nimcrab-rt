# screenshot.nim — silent desktop screenshot via GDI BitBlt
#
# Returns BMP bytes in memory. No new process, no WinRT.

import winim

proc captureScreen*(): seq[byte] =
  # unsafe
  let width  = GetSystemMetrics(SM_CXSCREEN)
  let height = GetSystemMetrics(SM_CYSCREEN)

  let hScreen = GetDC(0.HWND)
  if hScreen == 0: return @[]

  let hMem = CreateCompatibleDC(hScreen)
  let hBmp = CreateCompatibleBitmap(hScreen, width, height)
  let hOld = SelectObject(hMem, cast[HGDIOBJ](hBmp))

  discard BitBlt(hMem, 0, 0, width, height, hScreen, 0, 0, SRCCOPY)

  var bmi: BITMAPINFO
  zeroMem(addr bmi, sizeof(bmi))
  bmi.bmiHeader.biSize        = DWORD(sizeof(BITMAPINFOHEADER))
  bmi.bmiHeader.biWidth       = width
  bmi.bmiHeader.biHeight      = -height  # top-down
  bmi.bmiHeader.biPlanes      = 1
  bmi.bmiHeader.biBitCount    = 32
  bmi.bmiHeader.biCompression = BI_RGB

  let pixelBytes = width * height * 4
  var pixels = newSeq[byte](pixelBytes)
  discard GetDIBits(hMem, hBmp, 0, UINT(height),
                    addr pixels[0], addr bmi, DIB_RGB_COLORS)

  # Compose BMP file header (14 bytes) + DIB header (40 bytes) + pixels
  let fileSize = 54 + pixelBytes
  var bmp = newSeq[byte](fileSize)

  # BMP signature
  bmp[0] = byte('B'); bmp[1] = byte('M')
  cast[ptr uint32](addr bmp[2])[]  = uint32(fileSize)
  cast[ptr uint32](addr bmp[6])[]  = 0'u32      # reserved
  cast[ptr uint32](addr bmp[10])[] = 54'u32     # pixel data offset

  # DIB header
  cast[ptr uint32](addr bmp[14])[] = uint32(sizeof(BITMAPINFOHEADER))
  cast[ptr int32](addr bmp[18])[]  = int32(width)
  cast[ptr int32](addr bmp[22])[]  = int32(-height)
  cast[ptr uint16](addr bmp[26])[] = 1'u16      # planes
  cast[ptr uint16](addr bmp[28])[] = 32'u16     # biBitCount
  cast[ptr uint32](addr bmp[30])[] = BI_RGB     # biCompression
  cast[ptr uint32](addr bmp[34])[] = uint32(pixelBytes)
  # remaining fields (XPels, YPels, ClrUsed, ClrImportant) stay zero

  copyMem(addr bmp[54], addr pixels[0], pixelBytes)

  discard SelectObject(hMem, hOld)
  discard DeleteObject(cast[HGDIOBJ](hBmp))
  discard DeleteDC(hMem)
  discard ReleaseDC(nil, hScreen)

  bmp
