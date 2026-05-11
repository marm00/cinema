#ifndef CIN_WINDOW_POSIX_h
#define CIN_WINDOW_POSIX_h

#include <assert.h>
#include <dlfcn.h>

#include "base/core.h"
#include "console/log.h"

typedef struct _XDisplay Display;
typedef unsigned long XID;
typedef XID Window;
typedef XID Drawable;
typedef int Status;
typedef int Bool;
typedef struct _XErrorEvent XErrorEvent;

static_assert(sizeof(Window) == sizeof(HWND), "Changed types");

typedef Display *(*fn_XOpenDisplay)(const char *);
typedef int (*fn_XCloseDisplay)(Display *);
typedef Window (*fn_XDefaultRootWindow)(Display *);
typedef Status (*fn_XQueryTree)(Display *, Window, Window *, Window *, Window **, unsigned int *);
typedef int (*fn_XFetchName)(Display *, Window, char **);
typedef Status (*fn_XGetGeometry)(Display *, Drawable, Window *, int *, int *, unsigned int *, unsigned int *, unsigned int *, unsigned int *);
typedef int (*fn_XMoveResizeWindow)(Display *, Window, int, int, unsigned int, unsigned int);
typedef Bool (*fn_XTranslateCoordinates)(Display *, Window, Window, int, int, int *, int *, Window *);
typedef int (*fn_XSetErrorHandler)(int (*handler)(Display *, XErrorEvent *));
typedef int (*fn_XFlush)(Display *);
typedef int (*fn_XSync)(Display *, Bool);
typedef int (*fn_XFree)(void *);

extern void *pxlib;
extern Display *pxdisplay;

extern fn_XOpenDisplay pXOpenDisplay;
extern fn_XCloseDisplay pXCloseDisplay;
extern fn_XDefaultRootWindow pXDefaultRootWindow;
extern fn_XQueryTree pXQueryTree;
extern fn_XFetchName pXFetchName;
extern fn_XGetGeometry pXGetGeometry;
extern fn_XMoveResizeWindow pXMoveResizeWindow;
extern fn_XTranslateCoordinates pXTranslateCoordinates;
extern fn_XSetErrorHandler pXSetErrorHandler;
extern fn_XFlush pXFlush;
extern fn_XSync pXSync;
extern fn_XFree pXFree;

#define XLOAD(symbol)                                                      \
  do {                                                                     \
    assert(pxlib);                                                         \
    *(void **)(&p##symbol) = dlsym(pxlib, #symbol);                        \
    if (!p##symbol) {                                                      \
      log_message(LOG_DEBUG, "Failed to load %s: %s", #symbol, dlerror()); \
      return false;                                                        \
    }                                                                      \
  } while (0)

int xerror_handler(Display *d, XErrorEvent *e);
bool init_xlib(void);
Window find_window_by_name(Display *dsp, Window curr, const char *name);

#endif