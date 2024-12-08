import { NextResponse } from 'next/server';
import { getUserFromSession } from '@/src/lib/session';

export async function GET(request: Request) {
  const sessionId = request.cookies.get('sessionId')?.value;

  if (!sessionId) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  const user = await getUserFromSession(sessionId);

  if (!user) {
    return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
  }

  return NextResponse.json({ user });
}

