<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Assets & Media</h1>
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

    <div class="mt-5 flex flex-col">
      <div class="flex flex-row">
        <sl-button variant="primary" @click="onUploadAssetClicked" :loading="loading">
          <CloudArrowUpIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          Upload Asset
        </sl-button variant="primary">

        <sl-button variant="primary" class="ml-4" @click="openNewFolderDialog">
          <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          New Folder
        </sl-button variant="primary">
      </div>

      <div class="flex mt-6">
        <nav class="flex" aria-label="Breadcrumb">
          <ol role="list" class="flex items-center">
            <li v-for="item in navigation" :key="item.path">
              <div class="flex items-center">
                <svg class="h-5 w-5 flex-shrink-0 text-gray-300" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                  <path d="M5.555 17.776l8-16 .894.448-8 16-.894-.448z" />
                </svg>
                <RouterLink :to="{ query: { folder: item.path }}" class="-ml-0.5 text-sm font-medium text-neutral-600 hover:text-(--primary-color)">
                {{ item.folder }}
                </RouterLink>
              </div>
            </li>
          </ol>
        </nav>
      </div>

      <div class="flex mt-3">
        <AssetsList :assets="assets" @delete="onDeleteAssetClicked" @assetdbclicked="onAssetDbClicked" />
      </div>
    </div>
  </div>

  <DeleteDialog v-model="showDeleteAssetDialog" :error="deleteAssetDialogError"
    :title="deleteAssetDialogTitle" :message="deleteAssetDialogMessage" :loading="deleteAssetDialogLoading"
    @delete="deleteAsset" />

  <input type="file" class="hidden" ref="filesInput" multiple v-on:change="handleMediaUpload(true)" />

  <AssetDialog v-if="website && assetToInspect " v-model="showAssetDialog" :asset="assetToInspect" :website="website" />

  <!-- we remove the component from the DOM with v-if to avoid wasting resources (iframes...) -->
  <newAssetFolderDialog v-if="showNewAssetFolderDialog" v-model="showNewAssetFolderDialog"
    :website-id="websiteId" :folder="folder" @created="onFolderCreated" />
</template>

<script lang="ts" setup>
import { AssetType, type Asset, type ListAssetsInput, type UploadAssetInput, type Website, type GetWebsiteInput } from '@/api/model';
import { onBeforeMount, ref, watch, type Ref, computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { CloudArrowUpIcon, PlusIcon } from '@heroicons/vue/24/outline';
import AssetsList from '@/ui/components/websites/assets_list.vue';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { MAX_ASSET_SIZE } from '@/api/model';
import AssetDialog from '@/ui/components/content/asset_dialog.vue';
import NewAssetFolderDialog from '@/ui/components/content/new_asset_folder_dialog.vue';
import { useMdninja } from '@/api/mdninja';
import filesize from '@/libs/filesize';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

type NavigationItem = {
  folder: string;
  path: string;
}

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();
const $router = useRouter();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;
const deleteAssetDialogTitle = 'Delete Asset';
const deleteAssetDialogMessage = 'Are you sure you want to delete this asset? This action cannot be undone.';

let loading = ref(false);
let error = ref('');
let showDeleteAssetDialog = ref(false);
let deleteAssetDialogError = ref('');
let deleteAssetDialogLoading = ref(false);
let assetIdToDelete: Ref<string | null> = ref(null);
let filesToUpload: File[] = [];
const filesInput = ref(null);
let assets: Ref<Asset[]> = ref([]);
let folder = ref(($route.query.folder as string | undefined) ?? '/assets');
let website: Ref<Website | null> = ref(null);

let showAssetDialog = ref(false);
let assetToInspect: Ref<Asset | null> = ref(null);

let showNewAssetFolderDialog = ref(false);

// computed
const navigation = computed((): NavigationItem[] => {
  let parts = folder.value.split('/');

  const res = parts.reduce((acc, part) => {
    if (part.length === 0) {
      return acc;
    }

    acc.path = `${acc.path}/${part}`;
    acc.items.push({
      folder: part,
      path: acc.path,
    });
    return acc;
  }, { path: '', items: [] as NavigationItem[] });

  return res.items;
});

// watch
watch($route, (to) => {
  folder.value = (to.query.folder as string | undefined) ?? '/assets';
  $router.push({ query: { folder: folder.value } });
  assets.value = [];
  fetchData();
}, { deep: true });

// functions
function openNewFolderDialog() {
  showNewAssetFolderDialog.value = true;
}

function onFolderCreated(newFolder: Asset) {
  assets.value.push(newFolder);
  showNewAssetFolderDialog.value = false;
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const getAssetsInput: ListAssetsInput = {
    website_id: websiteId,
    folder: folder.value,
  };
  const getWebsiteInput: GetWebsiteInput = {
    id: websiteId,
  };

  try {
    // we can reduce the number of requests by requesting website only if website === null
    // but it complicates the code so it might not be worth
    const [websiteApi, assetsApi] = await Promise.all([
      $mdninja.getWebsite(getWebsiteInput),
      $mdninja.listAssets(getAssetsInput),
    ]);
    website.value = websiteApi;
    assets.value = assetsApi;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onDeleteAssetClicked(assetId: string) {
  assetIdToDelete.value = assetId;
  showDeleteAssetDialog.value = true;
}

function onAssetDbClicked(asset: Asset) {
  if (asset.type === AssetType.Folder) {
    $router.push({ query: { folder: `${asset.folder}/${asset.name}` } });
  } else {
    assetToInspect.value = asset;
    showAssetDialog.value = true;
  }
}

async function deleteAsset() {
  deleteAssetDialogLoading.value = true;
  deleteAssetDialogError.value = '';

  try {
    await $mdninja.deleteAsset(assetIdToDelete.value!);
    assets.value = assets.value.filter((asset: Asset) => asset.id !== assetIdToDelete.value!);
    assetIdToDelete.value = null;
    showDeleteAssetDialog.value = false;
  } catch (err: any) {
    deleteAssetDialogError.value = err.message;
  } finally {
    deleteAssetDialogLoading.value = false;
  }
}

function onUploadAssetClicked() {
  ((filesInput.value!) as HTMLElement).click();
}

async function handleMediaUpload(direct: boolean) {
  if (direct) {
    filesToUpload = ((filesInput.value!) as HTMLInputElement).files as unknown as File[];
  }

  if (!filesToUpload || filesToUpload.length === 0) {
    loading.value = false;
    return;
  }


  error.value = '';
  loading.value = true;

  // TODO: progress
  for (let i = 0; i < filesToUpload.length; i += 1) {
    const file = filesToUpload[i];
    if (file.size > MAX_ASSET_SIZE) {
      error.value = `Asset is too large. The current size limit is: ${filesize(MAX_ASSET_SIZE)}`;
      break;
    }

    const uploadAssetInput: UploadAssetInput = {
      website_id: websiteId,
      file: file,
      folder: folder.value,
    }

    try {
     const newAsset = await $mdninja.uploadAsset(uploadAssetInput);
     assets.value.push(newAsset);
    } catch (err: any) {
      error.value = err.message;
      break;
    }
  }

  loading.value = false;
}
</script>
