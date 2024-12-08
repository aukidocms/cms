import { Button } from '@/components/ui/button'
import Link from 'next/link'
import { ArrowRight, BookOpen, Users } from 'lucide-react'

export default function Home() {
  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-12 sm:py-16 lg:py-20">
      <div className="max-w-4xl mx-auto text-center">
        <h1 className="text-3xl font-bold mb-6">
          Welcome to Our Blog Platform
        </h1>
        <p className="text-xl text-muted-foreground mb-8">
          Discover insightful articles, share your thoughts, and connect with a community of writers and readers.
        </p>
        <div className="flex flex-col sm:flex-row justify-center gap-4">
          <Button asChild size="lg">
            <Link href="/blog">
              <BookOpen className="mr-2 h-5 w-5" />
              Explore Articles
            </Link>
          </Button>
          <Button asChild variant="outline" size="lg">
            <Link href="/about">
              <Users className="mr-2 h-5 w-5" />
              About Us
            </Link>
          </Button>
        </div>
      </div>
      <div className="mt-16 max-w-3xl mx-auto">
        <h2 className="text-2xl font-semibold mb-6 text-center">Featured Posts</h2>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            { title: "Getting Started with Next.js", excerpt: "Learn the basics of Next.js and start building modern web applications." },
            { title: "The Power of TypeScript", excerpt: "Discover how TypeScript can improve your JavaScript development experience." },
          ].map((post, index) => (
            <div key={index} className="bg-card text-card-foreground rounded-lg shadow-md p-6">
              <h3 className="text-lg font-semibold mb-2">{post.title}</h3>
              <p className="text-sm text-muted-foreground mb-4">{post.excerpt}</p>
              <Button variant="link" asChild>
                <Link href={`/blog/${post.title.toLowerCase().replace(/ /g, '-')}`}>
                  Read More <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

