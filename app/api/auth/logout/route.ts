import { NextResponse, NextRequest } from 'next/server';
import { deleteSession } from '@/src/lib/session';

export async function POST(request: NextRequest) {
  const sessionId = request.cookies.get('sessionId')?.value;

  if (sessionId) {
    await deleteSession(sessionId);
  }

  const response = NextResponse.json({ success: true });
  response.cookies.set('sessionId', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    expires: new Date(0),
    path: '/',
  });

  return response;
}

