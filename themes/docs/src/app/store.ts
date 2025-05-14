import { defineStore } from 'pinia'
import type { Contact, Page, PageMetadata, Tag, Website } from './model';

export interface AppState {
  loading: boolean,
  contact: Contact | null,
  website: Website | null,
  initialPage: Page | null,
  showAnnouncementBar: boolean,
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
    setShowAnnouncementBar(show: boolean) {
      this.showAnnouncementBar = show;
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
  getters: {
    announcement(): string | null {
      return this.showAnnouncementBar
        ? (this.website?.announcement ?? null)
        : null;
    }
  }
})

function defaultAppState(): AppState {
  return {
    loading: false,
    contact: null,
    website: null,
    initialPage: null,
    showAnnouncementBar: true,
    country: "XX",
    showSearchbar: false,

    allPages: [],
    allTags: [],

    sidebarOpen: false,
  };
}


// let store: Store | null = null;

// export function createStore() {
//   store = new Store();
// }

// export function useStore(): Store {
//   if (!store) {
//     throw new Error("Store must be instantiated before being used");
//   }

//   return store;
// }


// export class Store {
//   public loading: Ref<boolean>;
//   public contact: Ref<Contact | null>;
//   public website: Ref<Website | null>;
//   public initialPage: Ref<Page | null>;
//   public showAnnouncementBar: Ref<boolean>;
//   public announcement: ComputedRef<string | null>;

//   constructor() {
//     this.loading = ref(false);
//     this.contact = ref(null);
//     this.website = ref(null);
//     this.initialPage = ref(null);
//     this.showAnnouncementBar = ref(true);
//     this.announcement = computed(() => {
//       return this.showAnnouncementBar.value
//             ? (this.website.value?.announcement ?? null)
//             : null;
//     });
//   }

//   setWebsite(website: Website) {
//     this.website.value = website;
//   }

//   setLoading(loading: boolean) {
//           this.loading.value = loading;
//         }
//         setContact(contact: Contact) {
//           this.contact.value = contact;
//         }
//         updateContact(input: UpdateContact) {
//           if (!this.contact.value) {
//             return;
//           }

//           this.contact.value.email = input.email ?? this.contact.value.email;
//           this.contact.value.name = input.name ?? this.contact.value.name;
//         }
//         clear() {
//           this.loading = ref(false);
//           this.contact = ref(null);
//           this.website = ref(null);
//           this.initialPage = ref(null);
//           this.showAnnouncementBar = ref(true);
//         }
//         setInitialPage(page: Page | null) {
//           this.initialPage.value = page;
//         }
//         setShowAnnouncementBar(show: boolean) {
//           this.showAnnouncementBar.value = show;
//         }

//     //   getters: {
//     //     announcement(): string | null {
//     //       return this.showAnnouncementBar
//     //         ? (this.website?.announcement ?? null)
//     //         : null;
//     //     }
//     //   }
// }
