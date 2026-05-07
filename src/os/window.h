#ifndef CIN_WINDOW_H
#define CIN_WINDOW_H

#include "base/core.h"

bool cin_iswindow(HWND window);
bool cin_isvisible(HWND window);
int32_t cin_getwindow(HWND window, RECT *out_rect);
int32_t cin_movewindow(HWND window, RECT rect);

#endif