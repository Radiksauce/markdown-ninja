<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-5">
      <h1 class="text-3xl font-extrabold text-gray-900">Domains</h1>
    </div>

    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div v-if="website" class="flex flex-col">
      <div class="flex w-full max-w-md">
        <SlugInput v-model="slug" />
      </div>

      <div class="flex flex-row mt-5">
        <sl-button variant="primary" @click="updateSlug()" :loading="loading">
          Save
        </sl-button>
      </div>

      <div class="flex flex-col mt-10">
        <h2 class="text-xl font-medium">Primary domain</h2>
        <p>All other domains will redirect to your primary domain.</p>
        <SelectPrimaryDomain v-model="selectedPrimaryDomain" :domains="domainsToSelect" />
      </div>

      <div class="flex flex-row mt-5">
        <div class="flex">
          <sl-button variant="primary" :loading="loading" @click="setDomainAsPrimary()">
            Save
          </sl-button>
        </div>
      </div>

      <div class="flex mt-10">
        <h2 class="text-xl font-medium">Custom Domains</h2>
      </div>

      <p>
        To configure a custom domain, please first create a <code>CNAME</code> DNS record pointing to
        <code>markdown.club</code>
      </p>

      <div class="flex mt-5 mb-2">
        <sl-button variant="primary" @click="openAddDomainDialog()">
          <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          Add Custom Domain
        </sl-button>
      </div>

      <div class="flex">
        <DomainsList :domains="domains" @delete="onDeleteDomainClicked" @check-tls="checkTlsForDomain" />
      </div>

    </div>

  </div>

  <AddDomainDialog v-model="showAddDomainDialog" :website-id="websiteId" @created="onDomainAdded" />

  <DeleteDialog v-model="showDeleteDomainDialog" :error="deleteDomainDialogError"
    :title="deleteDomainDialogTitle" :message="deleteDomainDialogMessage" :loading="deleteDomainDialogLoading"
    @delete="removeDomain"
  />
</template>

<script lang="ts" setup>
import type { Domain, GetWebsiteInput, SetDomainAsPrimaryInput, UpdateWebsiteInput, Website } from '@/api/model';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import SlugInput from '@/ui/components/websites/slug_input.vue';
import DomainsList from '@/ui/components/websites/domains_list.vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import AddDomainDialog from '@/ui/components/websites/add_domain_dialog.vue';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import SelectPrimaryDomain from '@/ui/components/websites/select_primary_domain.vue';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { useStore } from '@/app/store';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();
const $store = useStore();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;
const deleteDomainDialogTitle = 'Delete Domain';
const deleteDomainDialogMessage = 'Are you sure you want to delete this Domain? This action cannot be undone.';
const websitesRootDomain = $store.websitesBaseUrl.replace(/^http(s)?:\/\//g, '');

let website: Ref<Website | null> = ref(null);
let loading = ref(false);
let error = ref('');
let slug = ref('');
let showAddDomainDialog = ref(false);

let showDeleteDomainDialog = ref(false);
let deleteDomainDialogError = ref('');
let deleteDomainDialogLoading = ref(false);
let domainIdToDelete: Ref<string | null> = ref(null);
let domainsToSelect: Ref<string[]> = ref([]);
let selectedPrimaryDomain: Ref<string | undefined> = ref(undefined)

// computed
const domains = computed(() => website.value?.domains ?? []);

// watch

// functions
function resetValues() {
  slug.value = website.value!.slug;
  domainsToSelect.value = domains.value.map((d: Domain) => d.hostname);
  domainsToSelect.value.unshift(`${slug.value}.${websitesRootDomain}`);
  if (domainsToSelect.value.includes(website.value!.primary_domain)) {
    selectedPrimaryDomain.value = website.value!.primary_domain;
  } else {
    selectedPrimaryDomain.value = domainsToSelect.value[0];
  }
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetWebsiteInput = {
    id: websiteId,
    domains: true,
  };

  try {
    website.value = await $mdninja.getWebsite(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updateSlug() {
  loading.value = true;
  error.value = '';
  const input: UpdateWebsiteInput = {
    id: websiteId,
    slug: slug.value,
  };

  try {
    const domains = website.value!.domains;
    website.value = await $mdninja.updateWebsite(input);
    website.value.domains = domains;
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function setDomainAsPrimary() {
  loading.value = true;
  error.value = '';

  const newPrimaryDomain = selectedPrimaryDomain.value ?? null;
  const input: SetDomainAsPrimaryInput = {
    domain: newPrimaryDomain,
    website_id: websiteId,
  };

  try {
    await $mdninja.setDomainAsPrimary(input);
    if (newPrimaryDomain) {
      website.value!.primary_domain = newPrimaryDomain;
    } else {
      website.value!.primary_domain = `${slug.value}.${websitesRootDomain}`;
    }
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}


function openAddDomainDialog() {
  showAddDomainDialog.value = true;
}

function onDomainAdded(domain: Domain) {
  website.value!.domains!.push(domain);
  resetValues();
}

function onDeleteDomainClicked(domain: Domain) {
  domainIdToDelete.value = domain.id;
  showDeleteDomainDialog.value = true;
}

async function removeDomain() {
  deleteDomainDialogLoading.value = true;
  deleteDomainDialogError.value = '';

  try {
    await $mdninja.removeDomain(domainIdToDelete.value!);
    website.value!.domains = website.value!.domains!.filter((d: Domain) => d.id !== domainIdToDelete.value!);
    domainIdToDelete.value = null;
    showDeleteDomainDialog.value = false;
    resetValues();
  } catch (err: any) {
    deleteDomainDialogError.value = err.message;
  } finally {
    deleteDomainDialogLoading.value = false;
  }
}

async function checkTlsForDomain(domain: Domain) {
  loading.value = true;
  error.value = '';

  try {
    await $mdninja.checkTlsCertificateForDomain(domain.id);
    website.value!.domains = website.value!.domains!.map((d: Domain) => {
      if (d.id === domain.id) {
        d.tls_active = true;
      }
      return d;
    });

    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
