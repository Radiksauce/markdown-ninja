<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-5">
      <h1 class="text-3xl font-extrabold text-gray-900">Settings</h1>
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

    <div v-if="organization" class="flex flex-col">

      <div class="flex flex-col w-full">
        <sl-input label="Organization's Name" :value="name" @input="name = $event.target.value"
          :disabled="loading"
        />
      </div>

      <div class="flex mt-3">
        <sl-button variant="primary" @click="updateOrganization()" :loading="loading" :disabled="loading">
          Save
        </sl-button>
      </div>



      <div class="pt-8 grid grid-cols-1 gap-y-6 sm:grid-cols-6 sm:gap-x-6">
        <div class="sm:col-span-6">
          <h2 class="text-2xl font-medium text-red-500">Danger Zone</h2>
          <p class="mt-1 text-sm text-red-500">Irreversible and destructive actions.</p>
        </div>
      </div>

        <div class="flex flex-col">
          <div class="mt-5 flex">
            <sl-button variant="danger" @click="openDeleteOrganizationDialog()" :loading="loading" :disabled="loading">
              Delete Organization
            </sl-button>
          </div>
        </div>
      </div>

    </div>

  <DeleteDialog v-model="showDeleteOrganizationDialog" :error="deleteOrganizationDialogError"
    :title="deleteOrganizationDialogTitle" :message="deleteOrganizationDialogMessage" :loading="deleteOrganizationDialogLoading"
    @delete="deleteOrganization" />
</template>

<script lang="ts" setup>
import type { GetOrganizationInput, Organization, UpdateOrganizationInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { useRouter } from 'vue-router';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();
const $router = useRouter();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const organizationId = $route.params.organization_id as string;

let organization: Ref<Organization | null> = ref(null);
let loading = ref(false);
let error = ref('');
let showDeleteOrganizationDialog = ref(false);
let deleteOrganizationDialogError = ref('');
let deleteOrganizationDialogLoading = ref(false);

let name = ref('');

// computed
const deleteOrganizationDialogTitle = computed(() => `Delete ${organization.value?.name ?? 'organization'}`);
const deleteOrganizationDialogMessage = computed(() => `Are you sure you want to delete ${organization.value?.name ?? 'your organization'}? All of your data will be permanently removed from our servers forever. This action cannot be undone.`);

// watch

// functions
function resetValues() {
  name.value = organization.value!.name;
}

function openDeleteOrganizationDialog() {
  showDeleteOrganizationDialog.value = true;
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetOrganizationInput = {
    id: organizationId,
  };

  try {
    organization.value = await $mdninja.getOrganization(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updateOrganization() {
  loading.value = true;
  error.value = '';
  const input: UpdateOrganizationInput = {
    id: organizationId,
    name: name.value,
  };

  try {
    organization.value = await $mdninja.updateOrganization(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function deleteOrganization() {
  deleteOrganizationDialogLoading.value = true;
  deleteOrganizationDialogError.value = '';

  try {
    await $mdninja.deleteOrganization(organizationId);
    $router.push('/organizations');
  } catch (err: any) {
    deleteOrganizationDialogError.value = err.message;
  } finally {
    deleteOrganizationDialogLoading.value = false;
  }
}
</script>
