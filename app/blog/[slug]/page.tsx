import Link from 'next/link'
import { notFound } from 'next/navigation'
import { Badge } from '@/components/ui/badge'
import { db } from '@/src/db'
import { posts } from '@/src/db/schema'
import { eq } from 'drizzle-orm'
import ReactMarkdown from 'react-markdown'

async function getPost(slug: string) {
  const post = await db.select().from(posts).where(eq(posts.slug, slug)).limit(1);
  return post[0];
}

export default async function BlogPostPage({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug);

  if (!post) {
    notFound();
  }

  return (
    <div className="w-full">
      <div className="max-w-none px-4 sm:px-6 lg:px-8 py-6">
        <div className="mb-6">
          <div className="border border-gray-200 rounded-lg p-4 mb-4">
            <h1 className="text-4xl font-bold mb-2">{post.title}</h1>
            {post.subtitle && <p className="text-xl text-gray-600 mb-4">{post.subtitle}</p>}
            <div className="flex flex-wrap gap-2">
              {post.tags.map((tag) => (
                <Badge key={tag} variant="secondary">
                  <Link href={`/blog/tags/${tag}`}>
                    {tag}
                  </Link>
                </Badge>
              ))}
            </div>
          </div>
          <div className="border border-gray-200 rounded-lg p-4">
            <div className="prose dark:prose-invert max-w-none">
              <ReactMarkdown>{post.content}</ReactMarkdown>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

