import { Button } from '@/components/ui/button'
import Link from 'next/link'
import { Mail } from 'lucide-react'

export default function AboutPage() {
  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-12 sm:py-16 lg:py-20">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight mb-6">About Us</h1>
        <p className="text-xl text-muted-foreground mb-8">
          We are a passionate team of writers, developers, and creatives dedicated to bringing you high-quality content and fostering a community of knowledge sharing.
        </p>
        <div className="space-y-6">
          <h2 className="text-2xl sm:text-3xl font-semibold">Our Mission</h2>
          <p className="text-lg">
            Our mission is to create a platform where ideas flourish, knowledge is shared freely, and connections are made. We believe in the power of words to inspire, educate, and transform.
          </p>
          <h2 className="text-2xl sm:text-3xl font-semibold">What We Offer</h2>
          <ul className="list-disc pl-6 text-lg space-y-2">
            <li>Insightful articles on a wide range of topics</li>
            <li>A platform for both established and aspiring writers</li>
            <li>Community engagement through comments and discussions</li>
            <li>Regular updates on the latest trends and technologies</li>
          </ul>
          <h2 className="text-2xl sm:text-3xl font-semibold">Join Our Community</h2>
          <p className="text-lg">
            We're always looking for new voices and perspectives. Whether you're a reader, writer, or both, we invite you to be part of our growing community.
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            <Button asChild size="lg">
              <Link href="/blog">Explore Our Blog</Link>
            </Button>
            <Button asChild variant="outline" size="lg">
              <Link href="/contact">
                <Mail className="mr-2 h-5 w-5" />
                Contact Us
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}

