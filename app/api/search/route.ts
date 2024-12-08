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

