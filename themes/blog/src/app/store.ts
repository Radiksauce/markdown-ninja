import { defineStore } from 'pinia'
import type { Contact, Page, PageMetadata, Tag, Website } from './model';

export interface AppState {
  loading: boolean,
  contact: Contact | null,
  website: Website | null,
  initialPage: Page | null,
  country: string,
  showSearchbar: boolean,

  allPages: PageMetadata[],
  allTags: Tag[],

  sidebarOpen: boolean,
}

export interface UpdateContact {
  email?: string;
  name?: string;
}

export const useStore = defineStore('store', {
  state: () => defaultAppState(),
  actions: {
    setWebsite(website: Website) {
      this.website = website;
    },
    setLoading(loading: boolean) {
      this.loading = loading;
    },
    setContact(contact: Contact) {
      this.contact = contact;
    },
    updateContact(input: UpdateContact) {
      if (!this.contact) {
        return;
      }

      this.contact.email = input.email ?? this.contact.email;
      this.contact.name = input.name ?? this.contact.name;
    },
    clear() {
      this.$state = defaultAppState();
    },
    setInitialPage(page: Page | null) {
      this.initialPage = page;
    },
    setCountry(country: string) {
      this.country = country;
    },
    setAllPages(pages: PageMetadata[]) {
      this.allPages = pages;
    },
    setAllTags(tags: Tag[]) {
      this.allTags = tags;
    },
    setShowSearchbar(show: boolean) {
      this.showSearchbar = show;
    },
    toggleSidebar(open: boolean) {
      this.sidebarOpen = open;
    },
  },
})

function defaultAppState(): AppState {
  return {
    loading: false,
    contact: null,
    website: null,
    initialPage: null,
    country: "XX",
    showSearchbar: false,

    allPages: [],
    allTags: [],

    sidebarOpen: false,
  };
}
