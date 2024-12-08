import { NextResponse, NextRequest } from 'next/server';
import { db } from '@/src/db';
import { posts } from '@/src/db/schema';
import { eq, desc } from 'drizzle-orm';
import { getUserFromSession } from '@/src/lib/session';
import { Post } from '@/src/db/schema';

export async function GET(request: NextRequest, { params }: { params: { slug: string } }) {
  try {
    const sessionId = request.cookies.get('sessionId')?.value;
    if (!sessionId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const user = await getUserFromSession(sessionId);
    if (!user) {
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }

    if (params.slug === 'all') {
      // Fetch all posts
      const allPosts = await db.select().from(posts).orderBy(desc(posts.createdAt));
      return NextResponse.json(allPosts);
    } else {
      // Fetch single post
      const post = await db.select().from(posts).where(eq(posts.slug, params.slug)).limit(1);
      
      if (post.length === 0) {
        return NextResponse.json({ error: 'Post not found' }, { status: 404 });
      }
      
      return NextResponse.json(post[0]);
    }
  } catch (error) {
    console.error('Error fetching post(s):', error);
    return NextResponse.json({ error: 'Error fetching post(s)' }, { status: 500 });
  }
}

export async function PUT(request: NextRequest, { params }: { params: { slug: string } }) {
  try {
    const sessionId = request.cookies.get('sessionId')?.value;
    if (!sessionId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const user = await getUserFromSession(sessionId);
    if (!user) {
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }

    const body: Partial<Post> = await request.json();
    
    // Validate required fields
    if (!body.status) {
      return NextResponse.json({ error: 'Status is required' }, { status: 400 });
    }

    // Prepare the update object
    const updateData: Partial<Post> = {
      title: body.title,
      subtitle: body.subtitle,
      content: body.content,
      tags: body.tags,
      status: body.status as 'published' | 'draft',
      updatedAt: new Date(),
    };

    const result = await db.update(posts)
      .set(updateData)
      .where(eq(posts.slug, params.slug))
      .returning();
    
    if (result.length === 0) {
      return NextResponse.json({ error: 'Post not found' }, { status: 404 });
    }
    
    return NextResponse.json(result[0]);
  } catch (error) {
    console.error('Error updating post:', error);
    return NextResponse.json({ error: 'Error updating post' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, { params }: { params: { slug: string } }) {
  try {
    const sessionId = request.cookies.get('sessionId')?.value;
    if (!sessionId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const user = await getUserFromSession(sessionId);
    if (!user) {
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }

    const deletedPost = await db.delete(posts)
      .where(eq(posts.slug, params.slug))
      .returning();
   
    if (deletedPost.length === 0) {
      return NextResponse.json({ error: 'Post not found' }, { status: 404 });
    }
   
    return NextResponse.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Error deleting post:', error);
    return NextResponse.json({ error: 'Error deleting post' }, { status: 500 });
  }
}

