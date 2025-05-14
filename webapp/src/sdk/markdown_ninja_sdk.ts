let markdownNinjaClient: MarkdownNinjaClient | null = null;

export function createMarkdownNinjaClient(baseUrl: string): MarkdownNinjaClient {
  markdownNinjaClient = new MarkdownNinjaClient(baseUrl);
  return markdownNinjaClient;
}

export function useMarkdownNinja(): MarkdownNinjaClient {
  if (!markdownNinjaClient) {
    throw new Error('MarkdownNinjaClient should be created before using it');
  }
  return markdownNinjaClient!;
}


export type Page = {
  created_at: string,
  title: string,
  body: string,
}

export type ApiError = {
  message: string,
  code: string,
}


export class MarkdownNinjaClient {
  private baseUrl: string;

  // private currentUser: User | null;
  // private authBroadcastChannel: BroadcastChannel;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async getPage(slug: string): Promise<Page> {
    let url = new URL(this.baseUrl);
    url.pathname = '/__markdown_ninja/api/page';
    url.searchParams.append('slug', slug);

    return unwrapApiResponse(await fetch(url));
  }
}

async function unwrapApiResponse(response: Response): Promise<any>  {
  const apiRes: any = await response.json();

  if (response.status >= 400) {
    throw new Error(apiRes.message);
  }

  return apiRes;
}
