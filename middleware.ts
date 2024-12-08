import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { getUserFromSession } from '@/src/lib/session'

export const config = {
  matcher: '/admin/dashboard/:path*',
}

export async function middleware(request: NextRequest) {
  const sessionId = request.cookies.get('sessionId')?.value

  if (!sessionId) {
    return NextResponse.redirect(new URL('/admin', request.url))
  }

  const user = await getUserFromSession(sessionId)
  if (!user) {
    return NextResponse.redirect(new URL('/admin', request.url))
  }

  return NextResponse.next()
}

