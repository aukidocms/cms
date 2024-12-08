import Link from 'next/link'
import { notFound } from 'next/navigation'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { db } from '@/src/db'
import { posts } from '@/src/db/schema'
import { desc, sql } from 'drizzle-orm'

async function getPostsByTag(tag: string) {
  const taggedPosts = await db.select()
    .from(posts)
    .where(sql`${posts.tags} @> ARRAY[${tag}]::text[]`)
    .orderBy(desc(posts.createdAt));
  return taggedPosts;
}

export default async function TagPage({ params }: { params: { tag: string } }) {
  const { tag } = params;
  const taggedPosts = await getPostsByTag(tag);

  if (taggedPosts.length === 0) {
    notFound();
  }

  return (
    <div className="container py-8">
      <h1 className="text-3xl font-bold mb-8">Posts tagged with &quot;{tag}&quot;</h1>
      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {taggedPosts.map((post) => (
          <Card key={post.id} className="border border-gray-200 shadow-sm hover:shadow-md transition-shadow duration-200">
            <CardHeader>
              <CardTitle>
                <Link href={`/blog/${post.slug}`} className="hover:underline">
                  {post.title}
                </Link>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">
                {post.content.length > 100
                  ? `${post.content.substring(0, 100)}...`
                  : post.content}
              </p>
              <div className="flex flex-wrap gap-2 mt-2">
                {Array.isArray(post.tags) && post.tags.map((postTag) => (
                  <Badge 
                    key={postTag} 
                    variant={postTag === tag ? "default" : "secondary"}
                  >
                    <Link href={`/blog/tags/${postTag}`}>
                      {postTag}
                    </Link>
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

