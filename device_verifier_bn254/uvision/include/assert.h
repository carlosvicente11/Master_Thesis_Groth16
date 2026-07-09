#ifndef _ASSERT_H
#define _ASSERT_H

void abort(void);

#define assert(x) do { if (!(x)) abort(); } while(0)

#endif
