#include "window_posix.h"
#include "base/array.h"
#include "console/console.h"
#include "window.h"

void *pxlib = 0;
Display *pxdisplay = 0;
fn_XOpenDisplay pXOpenDisplay = 0;
fn_XCloseDisplay pXCloseDisplay = 0;
fn_XDefaultRootWindow pXDefaultRootWindow = 0;
fn_XQueryTree pXQueryTree = 0;
fn_XFetchName pXFetchName = 0;
fn_XGetGeometry pXGetGeometry = 0;
fn_XMoveResizeWindow pXMoveResizeWindow = 0;
fn_XTranslateCoordinates pXTranslateCoordinates = 0;
fn_XSetErrorHandler pXSetErrorHandler = 0;
fn_XFlush pXFlush = 0;
fn_XSync pXSync = 0;
fn_XFree pXFree = 0;

bool cin_iswindow(HWND window) {
  if (!pxlib || !window) return false;
  Window root;
  int x, y;
  unsigned int w, h, bw, d;
  Status status = pXGetGeometry(pxdisplay, window, &root, &x, &y, &w, &h, &bw, &d);
  return status != 0;
}

bool cin_isvisible(HWND window) {
  // NOTE: does not check window map state
  return cin_iswindow(window);
}

int32_t cin_getwindow(HWND window, RECT *out_rect) {
  if (!pxlib || !window) return 0;
  pXSetErrorHandler(xerror_handler);
  Window root;
  int x, y;
  unsigned int w, h, bw, d;
  Status status = pXGetGeometry(pxdisplay, window, &root, &x, &y, &w, &h, &bw, &d);
  if (status) {
    int screen_x, screen_y;
    Window child;
    status = pXTranslateCoordinates(pxdisplay, window, root, 0, 0, &screen_x, &screen_y, &child);
    if (status) {
      out_rect->left = screen_x - (int)bw;
      out_rect->top = screen_y - (int)bw;
      out_rect->right = screen_x + (int)w + (int)bw;
      out_rect->bottom = screen_y + (int)h + (int)bw;
    } else {
      log_message(LOG_ERROR, "Failed to translate window geometry");
    }
  } else {
    log_message(LOG_ERROR, "Failed to get window geometry");
  }
  pXFlush(pxdisplay);
  pXSetErrorHandler(NULL);
  return status;
}

int32_t cin_movewindow(HWND window, RECT rect) {
  const int32_t x = (int32_t)rect.left;
  const int32_t y = (int32_t)rect.top;
  const int32_t cx = (int32_t)rect.right;
  const int32_t cy = (int32_t)rect.bottom;
  assert(cx >= 0);
  assert(cy >= 0);
  int res = pXMoveResizeWindow(pxdisplay, window, x, y, (uint32_t)cx, (uint32_t)cy);
  pXSync(pxdisplay, false);
  return res;
}

int xerror_handler(Display *d, XErrorEvent *e) {
  (void)d;
  (void)e;
  return 0;
}

bool init_xlib(void) {
  if (!(pxlib = dlopen("libX11.so.6", RTLD_LAZY)) &&
      !(pxlib = dlopen("libX11.so", RTLD_LAZY))) {
    log_last_error("Failed to dlopen X11");
    return false;
  }
  XLOAD(XOpenDisplay);
  XLOAD(XCloseDisplay);
  XLOAD(XDefaultRootWindow);
  XLOAD(XQueryTree);
  XLOAD(XFetchName);
  XLOAD(XGetGeometry);
  XLOAD(XMoveResizeWindow);
  XLOAD(XTranslateCoordinates);
  XLOAD(XSetErrorHandler);
  XLOAD(XFlush);
  XLOAD(XSync);
  XLOAD(XFree);
  pxdisplay = pXOpenDisplay(NULL);
  if (!pxdisplay) {
    log_message(LOG_ERROR, "Failed to open default display");
    return false;
  }
  pXSetErrorHandler(xerror_handler);
  return true;
}

Window find_window_by_name(Display *dsp, Window curr, const char *name) {
  const size_t name_len = strlen(name);
  array_struct(Window) queue = {0};
  array_push(&arena_console, &queue, curr);
  Window result = 0;
  uint32_t i = 0;
  while (i < queue.count) {
    curr = queue.items[i++];
    Window root;
    Window parent;
    Window *children = NULL;
    uint32_t nchildren;
    if (!pXQueryTree(dsp, curr, &root, &parent, &children, &nchildren)) {
      log_last_error("Failed to query X11 window tree");
    } else {
      for (uint32_t j = 0; j < nchildren; ++j) {
        Window child = children[j];
        char *child_name = NULL;
        pXFetchName(dsp, child, &child_name);
        if (child_name) {
          log_message(LOG_TRACE, "Named child window: %s", child_name);
          const bool match = strncmp(child_name, name, name_len) == 0;
          pXFree(child_name);
          if (match) {
            log_message(LOG_DEBUG, "Child window is a match: %s", name);
            array_clear(&queue);
            result = child;
            break;
          }
        }
        array_push(&arena_console, &queue, child);
      }
    }
    if (children) pXFree(children);
  }
  array_free_items(&arena_console, &queue);
  return result;
}