import { NextResponse } from 'next/server';
import { getUserFromSession } from '@/src/lib/session';

export async function POST(request: Request) {
  const sessionId = request.cookies.get('sessionId')?.value;

  if (!sessionId) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  const user = await getUserFromSession(sessionId);
  if (!user) {
    return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
  }

  // TODO: Implement authorization check to ensure user has permission to deploy

  try {
    const deployHook = process.env.VERCEL_DEPLOY_HOOK;
    if (!deployHook) {
      throw new Error('Vercel Deploy Hook is not configured');
    }

    const response = await fetch(deployHook, {
      method: 'POST'
    });
    
    if (!response.ok) {
      throw new Error('Deployment failed');
    }

    return NextResponse.json({ message: 'Deployment triggered successfully' });
  } catch (error) {
    console.error('Deployment error:', error);
    return NextResponse.json({ error: 'Failed to trigger deployment' }, { status: 500 });
  }
}

