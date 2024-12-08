import Link from 'next/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { db } from '@/src/db'
import { posts } from '@/src/db/schema'
import { desc } from 'drizzle-orm'

async function getPosts() {
  const allPosts = await db.select().from(posts).orderBy(desc(posts.createdAt)).limit(10);
  return allPosts;
}

export default async function BlogPage() {
  const blogPosts = await getPosts();

  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-3xl font-bold mb-8">Blog Posts</h1>
      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {blogPosts.map((post) => (
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
                {post.tags && post.tags.map((tag) => (
                  <Badge key={tag} variant="secondary">
                    <Link href={`/blog/tags/${tag}`}>
                      {tag}
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

