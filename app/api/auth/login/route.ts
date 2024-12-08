
import { NextResponse, NextRequest } from 'next/server';
import { db } from '@/src/db';
import { users } from '@/src/db/schema';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';
import { createSession } from '@/src/lib/session';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password } = body;

    console.log('Attempting login for email:', email);

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password are required' }, { status: 400 });
    }

    // Find user by email
    const user = await db.select().from(users).where(eq(users.email, email)).limit(1);
    if (user.length === 0) {
      console.log('User not found');
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }

    console.log('User found, comparing password');

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user[0].password);
    if (!isPasswordValid) {
      console.log('Invalid password');
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }

    console.log('Password valid, creating session');

    // Create session
    const sessionId = await createSession(user[0].id);

    // Remove password from the response
    const { password: _, ...userWithoutPassword } = user[0];

    const response = NextResponse.json({ user: userWithoutPassword }, { status: 200 });
    response.cookies.set('sessionId', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60, // 24 hours
      path: '/',
    });

    return response;
  } catch (error) {
    console.error('Error logging in:', error);
    return NextResponse.json({ error: 'Error logging in' }, { status: 500 });
  }
}
[V0_FILE]typescriptreact:file="app/api/auth/me/route.ts"
import { NextResponse, NextRequest } from 'next/server';
import { getUserFromSession } from '@/src/lib/session';

export async function GET(request: NextRequest) {
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
[V0_FILE]typescriptreact:file="app/api/posts/route.ts"
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
[V0_FILE]typescriptreact:file="app/api/posts/[slug]/route.ts"
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
[V0_FILE]typescriptreact:file="app/api/search/route.ts"
import { NextResponse, NextRequest } from 'next/server';
import { db } from '@/src/db';
import { posts } from '@/src/db/schema';
import { desc, or, sql } from 'drizzle-orm';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const query = searchParams.get('q');

  if (!query) {
    return NextResponse.json({ error: 'Search query is required' }, { status: 400 });
  }

  try {
    const searchResults = await db.select({
      id: posts.id,
      title: posts.title,
      content: posts.content,
      slug: posts.slug,
      tags: posts.tags,
    })
      .from(posts)
      .where(
        or(
          sql`LOWER(${posts.title}) LIKE LOWER(${'%' + query + '%'})`,
          sql`LOWER(${posts.content}) LIKE LOWER(${'%' + query + '%'})`,
          sql`${posts.tags} @> ARRAY[LOWER(${query})]::text[]`
        )
      )
      .orderBy(desc(posts.createdAt))
      .limit(20);

    console.log('Search query:', query);
    console.log('Search results:', searchResults);

    return NextResponse.json(searchResults);
  } catch (error) {
    console.error('Error searching posts:', error);
    return NextResponse.json({ error: 'Error searching posts' }, { status: 500 });
  }
}
[V0_FILE]typescriptreact:file="app/api/deploy/route.ts"
import { NextResponse, NextRequest } from 'next/server';
import { getUserFromSession } from '@/src/lib/session';

export async function POST(request: NextRequest) {
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
