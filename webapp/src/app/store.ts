import type { InitData, Organization, PricingPlan, Website } from '@/api/model';
import { defineStore } from 'pinia'
import { ref } from 'vue';

export interface AppState {
  appLoaded: boolean;
  appLoadingError: string;
  organizations: Organization[];
  stripePublicKey: string | null;
  // country: string,
  contact_email: string;
  isAdmin: boolean;
  userId: string | null;
  userEmail: string | null;
  pricing: PricingPlan[],
  websites: Website[],

  pingooEndpoint: string,
  pingooAppId: string,
  websitesBaseUrl: string,
}

const usePrivateState = defineStore('private_store', () => {
  const country = ref('XX');
  return { country };
})

export const useStore = defineStore('store', {
  state: () => defaultAppState(),
  getters: {
    country(): string {
      const privateState = usePrivateState();
      return privateState.country;
    }
  },
  actions: {
    setInitData(initData: InitData) {
      this.stripePublicKey = initData.stripe_public_key;
      // this.country = initData.country;
      this.contact_email = initData.contact_email;
      this.pricing = initData.pricing;
      this.pingooAppId = initData.pingoo.app_id;
      this.pingooEndpoint = initData.pingoo.endpoint;
      this.websitesBaseUrl = initData.websites_base_url;

      const privateState = usePrivateState();
      privateState.country = initData.country;
    },
    setUserId(userId: string | null) {
      this.userId = userId;
    },
    clear() {
      this.$state = defaultAppState();
    },
    setAppLoaded() {
      this.appLoaded = true;
    },
    setAppLoadingError(err: string) {
      this.appLoadingError = err;
      this.appLoaded = false;
    },
    setOrganizations(organizations: Organization[]) {
      this.organizations = organizations;
    },
    addOrUpdateOrganization(organization: Organization) {
      let updated = false;
      this.organizations = this.organizations.map((org) => {
        if (org.id === organization.id) {
          updated = true;
          return organization
        }
        return org;
      });

      if (!updated) {
        this.organizations.push(organization);
      }
    },
    deleteOrganization(orgId: string) {
      this.organizations = this.organizations.filter((org) => org.id !== orgId);
    },
    setIsAdmin(isAdmin: boolean) {
      this.isAdmin = isAdmin;
    },
    setUserEmail(email: string) {
      this.userEmail = email;
    },
    addWebsites(websites: Website[]) {
      // merge and remove duplicates
      this.websites = websites.concat(this.websites.filter((website) => websites.findIndex((site) => site.id === website.id) < 0))
    },
    removeWebsites(websiteIds: string[]) {
      for (let websiteId of websiteIds) {
        this.websites = this.websites.filter((site) => site.id !== websiteId);
      }
    }
  },
})

function defaultAppState(): AppState {
  return {
    appLoaded: false,
    appLoadingError: '',
    organizations: [],
    // country: 'XX',
    userId: null,
    userEmail: null,
    isAdmin: false,
    pricing: [],
    websites: [],

    stripePublicKey: null,
    contact_email: '',
    pingooAppId: '',
    pingooEndpoint: '',
    websitesBaseUrl: '',
  };
}
