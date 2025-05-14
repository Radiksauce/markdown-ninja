import { useStore } from "./store";
import * as model from "./model";
import { Routes } from "./api_routes";
// import truncate from "@/libs/truncate";

type ApiError = {
  message: string;
  code: string;
}

const networkErrorMessage = 'Network error';
const API_BASE_URL = '/__markdown_ninja/api';
const INTERNAL_ERROR_MESSAGE = 'Internal Error. Please try again and contact support if the problem persists.';
export const ErrorLoadingPage: string = 'Something went wrong! Try reloading the page. If the problem persists, please update your web browser to the latest version.';



async function post<I>(route: string, data: I): Promise<any> {
  const url = `${API_BASE_URL}${route}`;
  let response: any = null;

  const headers = new Headers();
  headers.set('Accept', 'application/json');
  headers.set('Content-Type', 'application/json');

  try {
    response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(data),
    });
  } catch (err: any) {
    throw new Error(networkErrorMessage);
  }

  return await unwrapApiResponse(response);
}

async function get(route: string, data?: any): Promise<any> {
  let url = `${API_BASE_URL}${route}`;
  let response: any = null;
  if (data) {
    url += '?' + new URLSearchParams(data).toString();
  }

  const headers = new Headers();
  headers.set('Accept', 'application/json');

  try {
    response = await fetch(url, { headers });
  } catch (err: any) {
    throw new Error(networkErrorMessage);
  }

  return await unwrapApiResponse(response);
}

// async function upload(route: string, data: FormData): Promise<any> {
//   const url = `${API_BASE_URL}${route}`;
//   let response: any = null;

//   let headers = new Headers();
//   headers.set('Accept', 'application/json');

//   try {
//     response = await fetch(url, {
//       method: 'POST',
//       headers,
//       body: data,
//     });
//   } catch (err) {
//     throw new Error(networkErrorMessage);
//   }

//   return await unwrapApiResponse(response);
// }

async function unwrapApiResponse(response: Response): Promise<any>  {
  // if the status code is >= 500 or the response is not JSON then something has gone really wrong
  if (response.status >= 500 || !response.headers.get('Content-Type')?.includes('application/json')) {
    throw new Error(INTERNAL_ERROR_MESSAGE);
  }

  const apiRes: any = await response.json();

  if (response.status >= 400) {
    throw new Error((apiRes as ApiError).message);
  }

  return apiRes;
}

export async function initData(env: string) {
  const $store = useStore();

  if (window.__markdown_ninja_data) {
    const mdninjaData: model.MarkdownNinjaData = window.__markdown_ninja_data;
    window.__markdown_ninja_data = null;

    if (mdninjaData.website) {
      $store.setWebsite(mdninjaData.website);
    }
    if (mdninjaData.page) {
      $store.setInitialPage(mdninjaData.page)
    }
    if (mdninjaData.contact) {
      $store.setContact(mdninjaData.contact);
    }
    $store.setCountry(mdninjaData.country)
  } else {
    // if window.__markdown_ninja_data is not present it means we are in dev mode and need to fetch the data before load
    // TODO: catch error
    // let page: model.Page | null = null;
    let error: string | null = null;
    let website: model.Website | null = null;
    let contact: model.Contact | null = null;

    try {
      website = await get(Routes.website);
    } catch (err: any) {
      error = err.message;
    }
    if (website) {
      $store.setWebsite(website);
      setColorsCssVariables(website);
    }

    try {
      contact = await fetchMe();
    } catch (err: any) {
      error = err.message;
    }
    if (contact) {
      $store.setContact(contact);
    }
    if (error) {
      window.__markdown_ninja_error = error;
    }
  }
}

export function markdownNinjaError(): string | undefined {
  return window.__markdown_ninja_error;
};

export async function getPage(input: model.GetPageInput): Promise<model.Page | null> {
  let page: model.Page | null = null;

  try {
    page = await get(Routes.page, input);
  } catch (err: any) {
    if ((err.message as string).toLowerCase().includes("not found")) {
      page = null;
    } else {
      throw err
    }
  }
  return page;
}

function setColorsCssVariables(website: model.Website) {
  document.documentElement.style.setProperty("--mdninja-background", website.colors.background);
  document.documentElement.style.setProperty("--mdninja-text", website.colors.text);
  document.documentElement.style.setProperty("--mdninja-accent", website.colors.accent);
  if (website.colors.accent === website.colors.text) {
    addCssRule(`@layer components { a { text-decoration: underline; font-weight: 500; } }`);
  }
}

function addCssRule(rule: string) {
  // get the first stylesheet or create a new one
  let styleSheet;
  if (document.styleSheets.length > 0) {
    styleSheet = document.styleSheets[0];
  } else {
    const style = document.createElement('style');
    document.head.appendChild(style);
    styleSheet = style.sheet;
  }

  styleSheet!.insertRule(rule, styleSheet!.cssRules.length);
}


export async function listTags(): Promise<model.PaginatedResult<model.Tag>> {
  const tags: model.PaginatedResult<model.Tag> = await get(Routes.tags);
  const $store = useStore();
  $store.setAllTags(tags.data);
  return tags;
}

export async function listPages(input: model.ListPagesInput): Promise<model.PaginatedResult<model.PageMetadata>> {
  const pages: model.PaginatedResult<model.PageMetadata> = await get(Routes.pages, input);
  if (!input.tag) {
    const $store = useStore();
    $store.setAllPages(pages.data);
  }

  return pages;
}

// TODO: uncomment?
// The value of this data is relatively low...
export async function trackPage() {
  // const queryParameters = new URLSearchParams(window.location.search);

  // const input: model.TrackEventPageViewInput = {
  //   path: window.location.pathname,
  //   header_referrer: document.referrer,
  //   query_parameter_ref: truncate(queryParameters.get('ref') || ''),
  // };
  // await post(Routes.eventsPageView, input);
}

export async function login(email: string): Promise<model.LoginOutput> {
  const input: model.LoginInput = {
    email: email,
  };
  const posts: model.LoginOutput = await post(Routes.login, input);
  return posts;
}

export async function subscribe(input: model.SubscribeInput): Promise<model.SubscribeOutput> {
  return await post(Routes.subscribe, input);
}

export async function unsubscribe(input: model.UnsubscribeInput) {
  await post(Routes.unsubscribe, input);
}

export async function logout() {
  const $store = useStore();
  await post(Routes.logout, {});
  localStorage.clear();
  $store.clear();
  window.location.href = '/';
}

export async function completeSubscription(input: model.CompleteSubscriptionInput): Promise<model.Contact> {
 const $store = useStore();
  const contact: model.Contact = await post(Routes.completeSubscription, input);
  $store.setContact(contact);
  return contact;
}

export async function completeLogin(input: model.CompleteLoginInput): Promise<model.Contact> {
  const $store = useStore();
  const contact: model.Contact = await post(Routes.completeLogin, input);
  $store.setContact(contact);
  return contact;
}

export async function updateMyAccount(input: model.UpdateMyAccountInput): Promise<model.Contact> {
  const $store = useStore();

  const contact: model.Contact = await post(Routes.updateMyAccount, input);
  $store.setContact(contact);
  return contact;
}

export async function verifyEmail(input: model.VerifyEmailInput) {
  await post(Routes.verifyEmail, input);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// Products
//////////////////////////////////////////////////////////////////////////////////////////////////

export async function fetchMe(): Promise<model.Contact | null> {
  const contact: model.Contact | null = await get(Routes.me);
  return contact;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// Store
//////////////////////////////////////////////////////////////////////////////////////////////////

export async function placeOrder(input: model.PlaceOrderInput): Promise<model.PlaceOrderOutput> {
  const res: model.PlaceOrderOutput = await post(Routes.placeOrder, input);
  return res;
}

export async function completeOrder(input: model.CompleteOrderInput) {
  await post(Routes.completeOrder, input);
}

export async function cancelOrder(input: model.CancelOrderInput) {
  await post(Routes.cancelorder, input);
}

export async function listMyOrders(): Promise<model.PaginatedResult<model.Order>> {
  const orders: model.PaginatedResult<model.Order> = await get(Routes.myOrders);
  return orders;
}

export async function listMyProducts(): Promise<model.PaginatedResult<model.Product>> {
  return await get(Routes.myProducts);
}

export async function getProduct(input: model.GetProductInput): Promise<model.Product> {
  return await get(Routes.product, input);
}

export async function deleteMyAccount() {
  const $store = useStore();
  await post(Routes.deleteMyAccount, {});
  localStorage.clear();
  $store.clear();
  window.location.href = '/';
}
