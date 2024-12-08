'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Trash, Plus, Pencil } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { useToast } from "@/components/ui/use-toast"
import { Post } from '@/src/db/schema'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export default function ManagePostsPage() {
  const [posts, setPosts] = useState<Post[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [deletePostSlug, setDeletePostSlug] = useState<string | null>(null)

  const router = useRouter()
  const { toast } = useToast()

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
          fetchPosts(); // Call fetchPosts here after authentication is confirmed
        } else {
          router.push('/admin');
        }
      } catch (error) {
        console.error('Error checking authentication:', error);
        router.push('/admin');
      }
    };

    checkAuth();
  }, [router]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchPosts()
    }
  }, [isAuthenticated])

  const fetchPosts = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/posts/all', {
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json();
        setPosts(data);
      } else {
        throw new Error('Failed to fetch posts');
      }
    } catch (error) {
      console.error('Error fetching posts:', error);
      toast({
        title: "Error",
        description: "Failed to fetch posts. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleTogglePublish = async (slug: string, currentStatus: string) => {
    const newStatus = currentStatus === 'published' ? 'draft' : 'published';
    
    // Optimistic update
    setPosts(posts.map(post => 
      post.slug === slug ? { ...post, status: newStatus, isLoading: true } : post
    ));

    try {
      const response = await fetch(`/api/posts/${slug}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: newStatus }),
        credentials: 'include',
      });
      
      if (response.ok) {
        const updatedPost = await response.json();
        setPosts(posts.map(post => post.slug === slug ? { ...updatedPost, isLoading: false } : post));
        toast({
          title: "Success",
          description: `Post ${newStatus === 'published' ? 'published' : 'unpublished'} successfully`,
        });
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to update post status');
      }
    } catch (error) {
      console.error('Error updating post status:', error);
      // Revert the optimistic update
      setPosts(posts.map(post => 
        post.slug === slug ? { ...post, status: currentStatus, isLoading: false } : post
      ));
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to update post status. Please try again.",
        variant: "destructive",
      });
    }
  };

  const handleDelete = async () => {
    if (deletePostSlug) {
      try {
        const response = await fetch(`/api/posts/${deletePostSlug}`, {
          method: 'DELETE',
          credentials: 'include',
        })
        if (response.ok) {
          setPosts(posts.filter(post => post.slug !== deletePostSlug))
          setDeletePostSlug(null)
          toast({
            title: "Success",
            description: "Post deleted successfully",
          })
        } else {
          throw new Error('Failed to delete post')
        }
      } catch (error) {
        console.error('Error deleting post:', error)
        toast({
          title: "Error",
          description: "Failed to delete post. Please try again.",
          variant: "destructive",
        })
      }
    }
  }

  if (!isAuthenticated) {
    return null
  }

  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-8">
      <Card>
        <CardHeader>
          <CardTitle className="text-2xl font-bold">Manage Posts</CardTitle>
          <CardDescription>
            Toggle publish status or delete your blog posts
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-6">
            <Button asChild>
              <Link href="/admin/dashboard/create-post">
                <Plus className="mr-2 h-4 w-4" />
                New Post
              </Link>
            </Button>
          </div>

          {isLoading ? (
            <div className="flex justify-center items-center py-8">
              <LoadingSpinner size="large" />
            </div>
          ) : (
            <div className="space-y-4">
              {posts.map((post) => (
                <Card key={post.slug} className="overflow-hidden">
                  <CardContent className="p-0">
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 space-y-4 sm:space-y-0">
                      <div className="flex items-center space-x-4">
                        <Avatar>
                          <AvatarImage src={post.authorAvatar || ''} />
                          <AvatarFallback>{post.authorName.split(' ').map(n => n[0]).join('')}</AvatarFallback>
                        </Avatar>
                        <div>
                          <h3 className="font-semibold">{post.title}</h3>
                          {post.subtitle && (
                            <p className="text-sm text-muted-foreground">{post.subtitle}</p>
                          )}
                          <div className="text-sm text-muted-foreground">
                            {new Date(post.createdAt).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2 sm:space-x-4 w-full sm:w-auto justify-between sm:justify-end">
                        <div className="flex items-center space-x-2">
                          <Switch
                            id={`publish-${post.slug}`}
                            checked={post.status === 'published'}
                            onCheckedChange={() => handleTogglePublish(post.slug, post.status)}
                            disabled={post.isLoading}
                          />
                          {post.isLoading && (
                            <LoadingSpinner size="small" />
                          )}
                          <Label
                            htmlFor={`publish-${post.slug}`}
                            className="text-sm cursor-pointer select-none"
                          >
                            {post.status === 'published' ? 'Published' : 'Draft'}
                          </Label>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => router.push(`/admin/dashboard/edit-post/${post.slug}`)}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setDeletePostSlug(post.slug)}
                          >
                            <Trash className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!deletePostSlug} onOpenChange={() => setDeletePostSlug(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete the post.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

