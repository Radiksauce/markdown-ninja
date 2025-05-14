<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
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

    <div v-if="website">
      <div class="flex flex-col space-y-5">

        <div class="flex w-full">
          <sl-input label="Website's Name" :value="name" @input="name = $event.target.value"
            :disabled="loading" />
        </div>

        <div class="flex w-full">
          <sl-textarea label="Website's Description" :value="description" @input="description = $event.target.value"
          :disabled="loading" />
        </div>


        <sl-switch :checked="poweredBy" @sl-change="poweredBy = $event.target.checked">
          Powered by Markdown Ninja
        </sl-switch>


        <sl-select :value="currency" @sl-change="currency = $event.target.value" label="Currency">
          <sl-option v-for="currency in allCurrencies" :value="currency">
            {{ currency }}
          </sl-option>
        </sl-select>

        <sl-textarea label="robots.txt" :value="robotsTxt" @input="robotsTxt = $event.target.value"
          placeholder="User-Agent: *&#10;Allow: /" :disabled="loading" rows="10"
        />

        <div v-if="$store.isAdmin" class="flex flex-col w-full">
          <sl-input label="Announcement" :value="announcement" @input="announcement = $event.target.value"
            :disabled="loading" />

          <sl-textarea label="Ad" :value="ad" @input="ad = $event.target.value"
            placeholder="Enter your HTML" :disabled="loading" rows="10"
            class="mt-5"
          />
        </div>


        <div class="flex">
          <sl-button variant="primary" @click="updateWebsite()" :loading="loading">
            Save
          </sl-button>
        </div>



        <div class="flex flex-col my-10">
          <h2 class="text-2xl font-medium text-red-500">Danger Zone</h2>
          <p class="mt-1 text-sm text-red-500">Irreversible and destructive actions.</p>

          <div class="mt-5 flex">
            <sl-button variant="danger" @click="openDeleteWebsiteDialog()">
              Delete Website
            </sl-button>
          </div>
        </div>
      </div>

    </div>


  </div>
  <DeleteDialog v-model="showDeleteWebsiteDialog" :error="deleteWebsiteDialogError"
    :title="deleteWebsiteDialogTitle" :message="deleteWebsiteDialogMessage" :loading="deleteWebsiteDialogLoading"
    @delete="deleteWebsite" />
</template>

<script lang="ts" setup>
import { allCurrencies, type DeleteWebsiteInput, type GetWebsiteInput, type UpdateWebsiteInput, type Website } from '@/api/model';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRouter } from 'vue-router';
import { useRoute } from 'vue-router';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { useMdninja } from '@/api/mdninja';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlSelect from '@shoelace-style/shoelace/dist/components/select/select.js';
import SlOption from '@shoelace-style/shoelace/dist/components/option/option.js';
import SlSwitch from '@shoelace-style/shoelace/dist/components/switch/switch.js';
import { useStore } from '@/app/store';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();
const $router = useRouter();
const $store = useStore();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;

let showDeleteWebsiteDialog = ref(false);
let deleteWebsiteDialogError = ref('');
let deleteWebsiteDialogLoading = ref(false);
let website: Ref<Website | null> = ref(null);
let loading = ref(false);
let error = ref('');
let robotsTxt = ref('');
let currency = ref('');
let ad = ref('');
let announcement = ref('');
let poweredBy = ref(true);

let name = ref('');
let description = ref('');



// computed
const deleteWebsiteDialogTitle = computed(() => `Delete ${website.value?.name ?? 'website'}`);
const deleteWebsiteDialogMessage = computed(() => `Are you sure you want to delete ${website.value?.name ?? 'you website'}? All of your data will be permanently removed from our servers forever. This action cannot be undone.`);
// watch

// functions
function resetValues() {
  name.value = website.value!.name;
  description.value = website.value!.description;
  robotsTxt.value = website.value!.robots_txt;
  currency.value = website.value!.currency;
  ad.value = website.value!.ad ?? '';
  announcement.value = website.value!.announcement ?? '';
  poweredBy.value = website.value!.powered_by;
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetWebsiteInput = {
    id: websiteId,
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

function openDeleteWebsiteDialog() {
  showDeleteWebsiteDialog.value = true;
}

async function deleteWebsite() {
  deleteWebsiteDialogLoading.value = true;
  deleteWebsiteDialogError.value = '';
  const input: DeleteWebsiteInput = {
    id: websiteId,
  };

  try {
    await $mdninja.deleteWebsite(input);
    $router.push(`/organizations/${website.value!.organization_id}`);
  } catch (err: any) {
    deleteWebsiteDialogError.value = err.message;
  } finally {
    deleteWebsiteDialogLoading.value = false;
  }
}

async function updateWebsite() {
  loading.value = true;
  error.value = '';
  const input: UpdateWebsiteInput = {
    id: websiteId,
    description: description.value,
    name: name.value,
    robots_txt: robotsTxt.value,
    currency: currency.value,
    ad: ad.value,
    announcement: announcement.value,
    powered_by: poweredBy.value,
  };

  try {
    website.value = await $mdninja.updateWebsite(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
