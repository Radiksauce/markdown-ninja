<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">API Keys</h1>
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

    <div v-if="organization">

      <div class="flex">
        <sl-button variant="primary" @click="openNewApiKeyDialog()">
          <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          New Api Key
        </sl-button>
      </div>

      <div class="flex">
        <ApiKeysList :keys="apiKeys" @delete="onDeleteApiKeyClicked" />
      </div>
    </div>

  </div>

  <PDeleteDialog v-model="showDeleteApiKeyDialog" :error="deleteApiKeyDialogError"
    :title="deleteApiKeyDialogTitle" :message="deleteApiKeyDialogMessage" :loading="deleteApiKeyDialogLoading"
    @delete="deleteApiKey"
  />

  <NewApiKeyDialog v-if="organization" v-model="showNewApiKeyDialog" :organizationId="organization.id" @created="onApiKeyCreated" />
</template>

<script lang="ts" setup>
import type { ApiKey, GetOrganizationInput, Organization } from '@/api/model';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import ApiKeysList from '@/ui/components/organizations/api_keys_list.vue';
import PDeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import NewApiKeyDialog from '@/ui/components/organizations/new_api_key_dialog.vue';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { useMdninja } from '@/api/mdninja';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const organizationId = $route.params.organization_id as string;
const deleteApiKeyDialogTitle = 'Delete API Key';
const deleteApiKeyDialogMessage = 'Are you sure you want to delete this API Key? This action cannot be undone.';

let organization: Ref<Organization | null> = ref(null);
let loading = ref(false);
let error = ref('');
let showDeleteApiKeyDialog = ref(false);
let deleteApiKeyDialogError = ref('');
let deleteApiKeyDialogLoading = ref(false);
let apiKeyIdToDelete: Ref<string | null> = ref(null);
let showNewApiKeyDialog = ref(false);

// computed
const apiKeys = computed(() => organization.value?.api_keys ?? []);

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetOrganizationInput = {
    id: organizationId,
    api_keys: true,
  };

  try {
    organization.value = await $mdninja.getOrganization(input);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function deleteApiKey() {
  deleteApiKeyDialogLoading.value = true;
  deleteApiKeyDialogError.value = '';

  try {
    await $mdninja.deleteApiKey(apiKeyIdToDelete.value!);
    organization.value!.api_keys = organization.value!.api_keys!.filter((apiKey) => apiKey.id !== apiKeyIdToDelete.value!);
    apiKeyIdToDelete.value = null;
    showDeleteApiKeyDialog.value = false;
  } catch (err: any) {
    deleteApiKeyDialogError.value = err.message;
  } finally {
    deleteApiKeyDialogLoading.value = false;
  }
}

function onApiKeyCreated(apiKey: ApiKey) {
  organization.value!.api_keys!.push(apiKey);
}

function openNewApiKeyDialog() {
  showNewApiKeyDialog.value = true;
}

function onDeleteApiKeyClicked(apiKey: ApiKey) {
  apiKeyIdToDelete.value = apiKey.id;
  showDeleteApiKeyDialog.value = true;
}
</script>
