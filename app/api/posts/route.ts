import { NextResponse, NextRequest } from 'next/server';
import { db } from '@/src/db';
import { posts } from '@/src/db/schema';
import { desc, eq, and, or, like, sql } from 'drizzle-orm';
import { getUserFromSession } from '@/src/lib/session';

function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)+/g, '');
}

export async function POST(request: NextRequest) {
  try {
    const sessionId = request.cookies.get('sessionId')?.value;
    if (!sessionId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const user = await getUserFromSession(sessionId);
    if (!user) {
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }

    const body = await request.json();
    const { title, subtitle, content, tags, status } = body;
    
    // Server-side validation
    const errors: Record<string, string> = {};
    if (!title || title.trim().length === 0) errors.title = 'Title is required';
    if (!content || content.trim().length === 0) errors.content = 'Content is required';
    if (!status || !['published', 'draft'].includes(status)) errors.status = 'Invalid status';
    if (Object.keys(errors).length > 0) {
      return NextResponse.json({ errors }, { status: 400 });
    }
    
    const slug = slugify(title);
    
    const newPost = await db.insert(posts).values({
      title,
      subtitle,
      content,
      tags,
      slug,
      authorName: user.name,
      authorEmail: user.email,
      status: status as 'published' | 'draft'
    }).returning();
    
    return NextResponse.json(newPost[0], { status: 201 });
  } catch (error) {
    console.error('Error creating post:', error);
    return NextResponse.json({ error: 'Error creating post' }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  try {
    const sessionId = request.cookies.get('sessionId')?.value;
    if (!sessionId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const user = await getUserFromSession(sessionId);
    if (!user) {
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '10');
    const status = searchParams.get('status');
    const search = searchParams.get('search');

    const offset = (page - 1) * limit;

    let query = db.select().from(posts);
    let countQuery = db.select({ count: sql<number>`count(*)` }).from(posts);

    if (status && status !== 'all') {
      const statusCondition = eq(posts.status, status);
      query = query.where(statusCondition);
      countQuery = countQuery.where(statusCondition);
    }

    if (search) {
      const searchCondition = or(
        like(posts.title, `%${search}%`),
        like(posts.content, `%${search}%`)
      );
      query = query.where(searchCondition);
      countQuery = countQuery.where(searchCondition);
    }

    query = query.orderBy(desc(posts.createdAt)).limit(limit).offset(offset);

    const [postsResult, countResult] = await Promise.all([
      query,
      countQuery
    ]);

    const totalPosts = countResult[0].count;
    const totalPages = Math.ceil(totalPosts / limit);

    return NextResponse.json({
      posts: postsResult,
      currentPage: page,
      totalPages: totalPages,
    });
  } catch (error) {
    console.error('Error fetching posts:', error);
    return NextResponse.json({ error: 'Error fetching posts' }, { status: 500 });
  }
}

