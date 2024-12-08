'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { toast } from '@/components/ui/use-toast'
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { AlertCircle, Info } from 'lucide-react'
import { Switch } from "@/components/ui/switch"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function CreatePostPage() {
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [post, setPost] = useState({
    title: '',
    subtitle: '',
    content: '',
    tags: '',
  })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errors, setErrors] = useState<{
    title?: string;
    subtitle?: string;
    content?: string;
    tags?: string;
    server?: string;
  }>({})
  const [isPublished, setIsPublished] = useState(false)
  const router = useRouter()

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/auth/me', { 
          credentials: 'include',
          headers: {
            'Cache-Control': 'no-cache',
          },
        });
        if (response.ok) {
          setIsAuthenticated(true);
        } else {
          router.push('/admin');
        }
      } catch (error) {
        console.error('Error checking authentication:', error);
        router.push('/admin');
      } finally {
        setIsLoading(false);
      }
    };

    checkAuth();
  }, [router]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target
    setPost(prev => ({ ...prev, [name]: value }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    setErrors({})

    // Client-side validation
    const newErrors: typeof errors = {}
    if (!post.title.trim()) newErrors.title = "Title is required"
    if (!post.content.trim()) newErrors.content = "Content is required"
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      setIsSubmitting(false)
      return
    }

    try {
      const response = await fetch('/api/posts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: post.title,
          subtitle: post.subtitle,
          content: post.content,
          tags: post.tags.split(',').map(tag => tag.trim()),
          status: isPublished ? 'published' : 'draft',
        }),
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        toast({
          title: "Success",
          description: `Post ${isPublished ? 'published' : 'saved as draft'} successfully`,
        })
        router.push('/admin/dashboard/manage-posts')
      } else {
        const errorData = await response.json()
        if (errorData.errors) {
          setErrors(errorData.errors)
        } else {
          throw new Error(errorData.error || 'Failed to create post')
        }
      }
    } catch (error) {
      console.error('Error creating post:', error)
      setErrors({ server: error instanceof Error ? error.message : 'An unexpected error occurred' })
      toast({
        title: "Error",
        description: "Failed to create post. Please try again.",
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  if (isLoading) {
    return (
      <div className="container mx-auto py-10 flex justify-center items-center min-h-[calc(100vh-4rem)]">
        <LoadingSpinner size="large" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="container mx-auto py-10">
      <Card className="max-w-2xl mx-auto">
        <CardHeader>
          <CardTitle>Create New Post</CardTitle>
        </CardHeader>
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4">
            {errors.server && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{errors.server}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-2">
              <Label htmlFor="title">Title</Label>
              <Input
                id="title"
                name="title"
                value={post.title}
                onChange={handleChange}
                required
              />
              {errors.title && <p className="text-sm text-red-500">{errors.title}</p>}
            </div>
            <div className="space-y-2">
              <Label htmlFor="subtitle">Subtitle</Label>
              <Input
                id="subtitle"
                name="subtitle"
                value={post.subtitle}
                onChange={handleChange}
              />
              {errors.subtitle && <p className="text-sm text-red-500">{errors.subtitle}</p>}
            </div>
            <div className="space-y-2">
              <Label htmlFor="content">Content</Label>
              <Alert>
                <Info className="h-4 w-4" />
                <AlertTitle>Markdown Shortcuts</AlertTitle>
                <AlertDescription>
                  <ul className="list-disc pl-4">
                    <li>Use '# ' for h1, '## ' for h2, '### ' for h3</li>
                    <li>Use '* ' or '- ' for bullet points</li>
                    <li>Use '1. ', '2. ', etc. for numbered lists</li>
                    <li>Use '**bold**' for <strong>bold text</strong></li>
                    <li>Use '*italic*' for <em>italic text</em></li>
                    <li>Use '`code`' for <code>inline code</code></li>
                    <li>Use '[link text](URL)' for links</li>
                    <li>Use {'\'> \''} for blockquotes</li>
                  </ul>
                </AlertDescription>
              </Alert>
              <Textarea
                id="content"
                name="content"
                value={post.content}
                onChange={handleChange}
                required
                className="min-h-[200px]"
              />
              {errors.content && <p className="text-sm text-red-500">{errors.content}</p>}
            </div>
            <div className="space-y-2">
              <Label htmlFor="tags">Tags (comma-separated)</Label>
              <Input
                id="tags"
                name="tags"
                value={post.tags}
                onChange={handleChange}
                placeholder="e.g. technology, programming, web development"
              />
              {errors.tags && <p className="text-sm text-red-500">{errors.tags}</p>}
            </div>
            <div className="flex items-center space-x-2">
              <Switch
                id="publish"
                checked={isPublished}
                onCheckedChange={setIsPublished}
              />
              <Label htmlFor="publish">Publish immediately</Label>
            </div>
          </CardContent>
          <CardFooter>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <LoadingSpinner size="small" className="mr-2" />
                  {isPublished ? 'Publishing...' : 'Saving Draft...'}
                </>
              ) : (
                isPublished ? 'Publish Post' : 'Save Draft'
              )}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}

                                    
