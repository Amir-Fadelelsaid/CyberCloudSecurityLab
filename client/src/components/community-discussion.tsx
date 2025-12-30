import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { formatDistanceToNow } from "date-fns";
import { 
  MessageSquare, 
  Send, 
  Trash2, 
  AlertCircle, 
  Users, 
  BookOpen,
  Reply,
  Shield
} from "lucide-react";

type User = {
  id: string;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  profileImageUrl: string | null;
};

type DiscussionPost = {
  id: number;
  userId: string;
  content: string;
  category: string | null;
  parentId: number | null;
  createdAt: string;
  user: User;
  replies: DiscussionPost[];
};

const CREATOR_USER_ID = "21487518";

export function CommunityDiscussion() {
  const { user: authUser } = useAuth();
  
  const isCreator = (userId: string) => userId === CREATOR_USER_ID;
  const { toast } = useToast();
  const [newPost, setNewPost] = useState("");
  const [replyContents, setReplyContents] = useState<Record<number, string>>({});
  const [replyingTo, setReplyingTo] = useState<number | null>(null);

  const getReplyContent = (postId: number) => replyContents[postId] || "";
  const setReplyContent = (postId: number, content: string) => {
    setReplyContents(prev => ({ ...prev, [postId]: content }));
  };

  const { data: posts, isLoading, isError, error } = useQuery<DiscussionPost[]>({
    queryKey: ["/api/discussions"],
    refetchInterval: 30000,
  });

  const { data: codeOfConduct } = useQuery<{ content: string }>({
    queryKey: ["/api/discussions/code-of-conduct"],
  });

  const createPostMutation = useMutation({
    mutationFn: async (data: { content: string; parentId?: number }) => {
      const res = await apiRequest("POST", "/api/discussions", data);
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.message);
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/discussions"] });
      setNewPost("");
      if (replyingTo) {
        setReplyContents(prev => ({ ...prev, [replyingTo]: "" }));
      }
      setReplyingTo(null);
      toast({ title: "Posted successfully" });
    },
    onError: (error: Error) => {
      toast({ 
        title: "Cannot post", 
        description: error.message,
        variant: "destructive" 
      });
    },
  });

  const deletePostMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("DELETE", `/api/discussions/${id}`);
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.message);
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/discussions"] });
      toast({ title: "Post deleted" });
    },
    onError: () => {
      toast({ title: "Cannot delete post", variant: "destructive" });
    },
  });

  const handleSubmit = () => {
    if (!newPost.trim()) return;
    createPostMutation.mutate({ content: newPost.trim() });
  };

  const handleReply = (parentId: number) => {
    const content = getReplyContent(parentId);
    if (!content.trim()) return;
    createPostMutation.mutate({ content: content.trim(), parentId });
  };

  const getUserName = (user: User) => {
    return user.displayName || 
      (user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Anonymous");
  };

  const getUserInitials = (user: User) => {
    const name = getUserName(user);
    return name.slice(0, 2).toUpperCase();
  };

  if (!authUser) {
    return (
      <Card className="border-yellow-500/30 bg-yellow-500/5">
        <CardContent className="p-6 text-center">
          <Shield className="w-12 h-12 mx-auto mb-4 text-yellow-500" />
          <h3 className="text-lg font-semibold mb-2">Join the Community</h3>
          <p className="text-muted-foreground">
            Sign in with Replit to participate in discussions and connect with other security professionals.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <Dialog>
          <DialogTrigger asChild>
            <Button variant="outline" size="sm" data-testid="button-code-of-conduct">
              <BookOpen className="w-4 h-4 mr-2" />
              Code of Conduct
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Community Code of Conduct</DialogTitle>
            </DialogHeader>
            <div className="prose prose-sm dark:prose-invert">
              <pre className="whitespace-pre-wrap font-sans text-sm">
                {codeOfConduct?.content || "Loading..."}
              </pre>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <MessageSquare className="w-4 h-4" />
            Start a Discussion
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            placeholder="Ask a question, share a tip, or discuss cloud security topics..."
            value={newPost}
            onChange={(e) => setNewPost(e.target.value)}
            className="min-h-[100px] resize-none"
            maxLength={2000}
            data-testid="input-new-discussion"
          />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">
              {newPost.length}/2000 characters
            </span>
            <Button 
              onClick={handleSubmit} 
              disabled={!newPost.trim() || createPostMutation.isPending}
              data-testid="button-post-discussion"
            >
              <Send className="w-4 h-4 mr-2" />
              {createPostMutation.isPending ? "Posting..." : "Post"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <MessageSquare className="w-4 h-4" />
        <span>{posts?.length || 0} discussions</span>
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="p-8 text-center">
            <div className="flex flex-col items-center gap-3">
              <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
              <span className="text-muted-foreground">Loading discussions...</span>
            </div>
          </CardContent>
        </Card>
      ) : isError ? (
        <Card className="border-destructive/30">
          <CardContent className="p-8 text-center">
            <AlertCircle className="w-12 h-12 mx-auto mb-4 text-destructive" />
            <h3 className="text-lg font-semibold mb-2">Failed to load discussions</h3>
            <p className="text-muted-foreground text-sm">
              {error instanceof Error ? error.message : "Please try refreshing the page."}
            </p>
          </CardContent>
        </Card>
      ) : posts && posts.length > 0 ? (
        <ScrollArea className="h-[500px] pr-4">
          <div className="space-y-4">
            {posts.map((post) => (
              <Card key={post.id} className="overflow-visible" data-testid={`discussion-post-${post.id}`}>
                <CardContent className="p-4">
                  <div className="flex gap-3">
                    <Avatar className="w-10 h-10 flex-shrink-0">
                      {post.user.profileImageUrl && (
                        <AvatarImage src={post.user.profileImageUrl} />
                      )}
                      <AvatarFallback className="bg-primary/10 text-primary text-sm">
                        {getUserInitials(post.user)}
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="font-medium text-sm">{getUserName(post.user)}</span>
                        {isCreator(post.userId) && (
                          <Badge className="bg-gradient-to-r from-primary to-emerald-400 text-black text-xs font-bold">
                            Creator
                          </Badge>
                        )}
                        <Badge variant="outline" className="text-xs">
                          {post.category || "general"}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {formatDistanceToNow(new Date(post.createdAt), { addSuffix: true })}
                        </span>
                      </div>
                      <p className="text-sm whitespace-pre-wrap break-words">{post.content}</p>
                      <div className="flex flex-wrap items-center gap-2 mt-3">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setReplyingTo(replyingTo === post.id ? null : post.id)}
                          data-testid={`button-reply-${post.id}`}
                        >
                          <Reply className="w-3 h-3 mr-1" />
                          Reply
                        </Button>
                        {post.userId === authUser?.id && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deletePostMutation.mutate(post.id)}
                            disabled={deletePostMutation.isPending}
                            className="text-destructive"
                            data-testid={`button-delete-${post.id}`}
                          >
                            <Trash2 className="w-3 h-3 mr-1" />
                            Delete
                          </Button>
                        )}
                      </div>

                      {replyingTo === post.id && (
                        <div className="mt-3 pl-4 border-l-2 border-primary/20">
                          <Textarea
                            placeholder="Write a reply..."
                            value={getReplyContent(post.id)}
                            onChange={(e) => setReplyContent(post.id, e.target.value)}
                            className="min-h-[80px] resize-none text-sm"
                            maxLength={2000}
                            data-testid={`input-reply-${post.id}`}
                          />
                          <div className="flex gap-2 mt-2">
                            <Button
                              size="sm"
                              onClick={() => handleReply(post.id)}
                              disabled={!getReplyContent(post.id).trim() || createPostMutation.isPending}
                              data-testid={`button-submit-reply-${post.id}`}
                            >
                              <Send className="w-3 h-3 mr-1" />
                              Reply
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setReplyingTo(null);
                                setReplyContent(post.id, "");
                              }}
                              data-testid={`button-cancel-reply-${post.id}`}
                            >
                              Cancel
                            </Button>
                          </div>
                        </div>
                      )}

                      {post.replies && post.replies.length > 0 && (
                        <div className="mt-4 space-y-3 pl-4 border-l-2 border-muted">
                          {post.replies.map((reply) => (
                            <div key={reply.id} className="flex gap-2" data-testid={`discussion-reply-${reply.id}`}>
                              <Avatar className="w-7 h-7 flex-shrink-0">
                                {reply.user.profileImageUrl && (
                                  <AvatarImage src={reply.user.profileImageUrl} />
                                )}
                                <AvatarFallback className="bg-muted text-xs">
                                  {getUserInitials(reply.user)}
                                </AvatarFallback>
                              </Avatar>
                              <div className="flex-1 min-w-0">
                                <div className="flex flex-wrap items-center gap-2 mb-1">
                                  <span className="font-medium text-xs">{getUserName(reply.user)}</span>
                                  {isCreator(reply.userId) && (
                                    <Badge className="bg-gradient-to-r from-primary to-emerald-400 text-black text-[10px] font-bold px-1.5 py-0">
                                      Creator
                                    </Badge>
                                  )}
                                  <span className="text-xs text-muted-foreground">
                                    {formatDistanceToNow(new Date(reply.createdAt), { addSuffix: true })}
                                  </span>
                                </div>
                                <p className="text-sm whitespace-pre-wrap break-words">{reply.content}</p>
                                {reply.userId === authUser?.id && (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => deletePostMutation.mutate(reply.id)}
                                    className="text-destructive mt-1"
                                    data-testid={`button-delete-reply-${reply.id}`}
                                  >
                                    <Trash2 className="w-3 h-3 mr-1" />
                                    Delete
                                  </Button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </ScrollArea>
      ) : (
        <Card>
          <CardContent className="p-8 text-center">
            <MessageSquare className="w-12 h-12 mx-auto mb-4 text-muted-foreground/50" />
            <h3 className="text-lg font-semibold mb-2">No discussions yet</h3>
            <p className="text-muted-foreground">
              Be the first to start a conversation with the community!
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
