<template>
  <div class="flex flex-col">

    <div class="flex flex-row justify-between items-center">
      <div class="flex items-center">
        <div class="flex">
          <RouterLink :to="backRoute">
            <sl-button outline>
              Back
            </sl-button>
          </RouterLink>
        </div>
        <div class="flex ml-5">
          <sl-button variant="primary" @click="updateProduct()" :loading="loading">
            Save
          </sl-button>
        </div>
      </div>
      <div class="flex flex-row">
        <div class="flex items-center mr-3">
          <div>
            <span v-if="product.status === ProductStatus.Draft" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200">
              Draft
            </span>
            <span v-else-if="product.status === ProductStatus.Active" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
              Published
            </span>
          </div>
        </div>
        <div class="flex">
          <sl-button variant="primary" v-if="product.status === ProductStatus.Draft" @click="publishProduct(true)" :loading="loading">
            Publish
          </sl-button>

          <Menu as="div" class="ml-4 relative inline-block text-left">
            <div>
              <MenuButton class="inline-flex w-full justify-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-xs ring-1 ring-inset ring-gray-300 hover:bg-gray-50">
                <!-- Options -->
                <EllipsisVerticalIcon class="h-5 w-5 text-gray-700" aria-hidden="true" />
              </MenuButton>
            </div>

            <transition enter-active-class="transition ease-out duration-100" enter-from-class="transform opacity-0 scale-95" enter-to-class="transform opacity-100 scale-100" leave-active-class="transition ease-in duration-75" leave-from-class="transform opacity-100 scale-100" leave-to-class="transform opacity-0 scale-95">
              <MenuItems class="absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-gray-300 focus:outline-none">
                <div class="py-1">
                  <MenuItem v-slot="{ active }" @click="openGiveAccessToProductDialog()">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Give access
                    </span>
                  </MenuItem>
                  <MenuItem v-slot="{ active }" @click="openExportCustomersForDialog()">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Export Customers
                    </span>
                  </MenuItem>
                  <MenuItem v-if="product.status === ProductStatus.Active" @click="publishProduct(false)" v-slot="{ active }">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Unpublish Product
                    </span>
                  </MenuItem>
                  <MenuItem v-slot="{ active }" @click="openRemoveAccessToProductDialog()">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Remove access
                    </span>
                  </MenuItem>
                  <MenuItem @click="openDeleteProductDialog" v-slot="{ active }">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Delete Product
                    </span>
                  </MenuItem>
                </div>
              </MenuItems>
            </transition>
          </Menu>
        </div>
      </div>
    </div>

    <div class="rounded-md bg-red-50 p-4 my-5" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex block mt-5">
      <div class="border-b border-gray-200">
        <nav class="-mb-px flex space-x-8" aria-label="Tabs">
          <span v-for="tab in tabs" :key="tab.value" @click="setCurrentTab(tab.value)"
            :class="[isCurrentTab(tab.value) ? 'border-(--primary-color) text-(--primary-color)' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700', ' cursor-pointer whitespace-nowrap border-b-2 py-4 px-1 text-sm font-medium']">
            {{ tab.name }}
          </span>
        </nav>
      </div>
    </div>


    <div class="flex flex-col" v-if="isDetailsTab(currentTab)">
      <div class="flex mt-5  w-full">
        <sl-input label="Name" :value="name" @input="name = $event.target.value" type="text"
          :disabled="loading" placeholder="My Product" />
      </div>

      <div class="flex w-full mt-5">
        <sl-input label="Price" :value="price" @input="price = parseInt($event.target.value, 10)" type="number"
          :disabled="loading" pattern="[0-9]*" />
      </div>

      <div class="flex flex-col mt-5 w-full">
        <sl-textarea label="Description" :value="description" @input="description = $event.target.value"
          rows="10" :disabled="loading"
        />
      </div>
    </div>

    <div class="flex flex-col" v-if="isAssetsTab(currentTab)">
      <div class="flex mt-5">
        <sl-button variant="primary" @click="onUploadAssetsClicked()" :loading="loading">
          <CloudArrowUpIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          Upload Asset
        </sl-button>
      </div>

      <div class="flex mt-5">
        <AssetsList :website="website" :assets="product.assets!" @delete="deleteAsset" />
      </div>
    </div>

    <div class="flex flex-col" v-if="isContentTab(currentTab)">
      <div class="flex mt-5">
        <sl-button variant="primary" @click="openNewProductPageDialog()"  :loading="loading">
          <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          {{ newPageButtonLabel }}
        </sl-button>
      </div>

      <div class="flex mt-5">
        <ProductPagesList :pages="product.content!" />
      </div>
    </div>
  </div>

  <NewProductPageDialog v-model="showNewProductPageDialog" :product-id="productId" @created="onProductPageCreated" />
  <GiveAccessToProductDialog v-model="showGiveAccessToProductDialog" :product-id="productId" />
  <ExportCustomersForProductDialog v-model="showExportCustomersForProductDialog" :product-id="productId" />
  <DeleteDialog v-model="showDeleteProductDialog" :error="deleteProductDialogError"
    :title="deleteProductDialogTitle" :message="deleteProductDialogMessage" :loading="deleteProductDialogLoading"
    @delete="deleteProduct"
  />
  <RemoveAccessToProductDialog v-model="showRemoveAccessToProductDialog" :product-id="productId" />

  <input type="file" class="hidden" ref="assetsInput" multiple v-on:change="handleAssetsUpload(true)" />
</template>

<script lang="ts" setup>
import {
  ProductType, type Product, type UpdateProductInput, type ProductPage,
  ProductStatus,
} from '@/api/model';
import { ref, type PropType, onBeforeMount } from 'vue';
import { useRoute } from 'vue-router';
import { PlusIcon, CloudArrowUpIcon } from '@heroicons/vue/24/outline';
import ProductPagesList from '@/ui/components/products/product_pages_list.vue';
import deepClone from 'mdninja-js/src/libs/deepclone';
import NewProductPageDialog from '@/ui/components/products/new_product_page_dialog.vue';
import { useRouter } from 'vue-router';
import AssetsList from './assets_list.vue';
import { MAX_ASSET_SIZE } from '@/api/model';
import type { Asset, DeleteProductInput, UploadAssetInput, Website } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/vue'
import { EllipsisVerticalIcon } from '@heroicons/vue/24/outline'
import GiveAccessToProductDialog from './give_access_to_product_dialog.vue';
import ExportCustomersForProductDialog from '@/ui/components/contacts/export_contacts_for_product_dialog.vue';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import RemoveAccessToProductDialog from './remove_access_to_product_dialog.vue';
import filesize from '@/libs/filesize';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { oneRouteUp } from '@/libs/router_utils';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';

// props
const props = defineProps({
  product: {
    type: Object as PropType<Product>,
    required: true,
  },
  website: {
    type: Object as PropType<Website>,
    required: true,
  },
});

// events
const $emit = defineEmits(['updated']);

// composables
const $route = useRoute();
const $router = useRouter();
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(() => resetValues());

// variables
const isBook = props.product.type === ProductType.Book;
const isCourse = props.product.type === ProductType.Course;
const isDownload = props.product.type === ProductType.Download;
const productId = $route.params.product_id as string;
const websiteId = $route.params.website_id as string;
const backRoute = oneRouteUp($route.path);
const tabs = getTabs();
const newPageButtonLabel = isCourse ? 'New Lesson' : 'New Page';
const deleteProductDialogTitle = 'Delete Product';
const deleteProductDialogMessage = 'Are you sure you want to delete this Product? This action cannot be undone.';

const assetsInput = ref(null);
let assetsToUpload: File[] = [];

let loading = ref(false);
let error = ref('');
let showNewProductPageDialog = ref(false);
let showGiveAccessToProductDialog = ref(false);
let currentTab = ref(tabs[0].value);
let showExportCustomersForProductDialog = ref(false);
let showRemoveAccessToProductDialog = ref(false);

let showDeleteProductDialog = ref(false);
let deleteProductDialogError = ref('');
let deleteProductDialogLoading = ref(false);

let name = ref('');
let description = ref('');
let status = ref(ProductStatus.Draft);
let price = ref(29);

// computed

// watch

// functions
function resetValues() {
  if (props.product) {
    name.value = props.product.name;
    description.value = props.product.description;
    status.value = props.product.status;
    price.value = props.product.price;
  } else {
    name.value = '';
    description.value = '';
    status.value = ProductStatus.Draft;
    price.value = 29;
  }
}

function isCurrentTab(tab: string): boolean {
  return currentTab.value === tab;
}

function setCurrentTab(tab: string) {
  currentTab.value = tab;
}

function isDetailsTab(tab: string): boolean {
  return tab === 'details';
}

function isContentTab(tab: string): boolean {
  return tab === 'content';
}

function isAssetsTab(tab: string): boolean {
  return tab === 'assets';
}

// function isFilesTab(tab: string): boolean {
//   return tab === 'files';
// }

function openNewProductPageDialog() {
  showNewProductPageDialog.value = true;
}

function openGiveAccessToProductDialog() {
  showGiveAccessToProductDialog.value = true;
}

function openRemoveAccessToProductDialog() {
  showRemoveAccessToProductDialog.value = true;
}

function openExportCustomersForDialog() {
  showExportCustomersForProductDialog.value = true;
}

function getTabs() {
   if (isBook || isCourse || isDownload) {
    return [
      { name: 'Lessons', value: 'content' },
      { name: 'Product Details', value: 'details' },
      { name: 'Assets', value: 'assets' },
    ];
  } else {
    return [
      { name: 'Product Details', value: 'details' },
    ];
  }
}

async function updateProduct() {
  error.value = '';
  let priceNumber = 0;
  try {
    priceNumber = price.value;
    if (isNaN(priceNumber)) {
      throw new Error();
    }
  } catch {
    error.value = 'Price is not valid';
  }

  loading.value = true;
  const input: UpdateProductInput = {
    id: productId,
    name: name.value,
    description: description.value,
    price: priceNumber,
  };


  try {
    const updatedProduct = await $mdninja.updateProduct(input);
    $emit('updated', updatedProduct);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onUploadAssetsClicked() {
  ((assetsInput.value!) as HTMLElement).click();
}

async function handleAssetsUpload(direct: boolean) {
  if (direct) {
    assetsToUpload = ((assetsInput.value!) as HTMLInputElement).files as unknown as File[];
  }

  if (!assetsToUpload || assetsToUpload.length === 0) {
    loading.value = false;
    return;
  }

  error.value = '';
  loading.value = true;

  // TODO: progress
  for (let i = 0; i < assetsToUpload.length; i += 1) {
    const file = assetsToUpload[i];
    if (file.size > MAX_ASSET_SIZE) {
      error.value = `File is too large. The current size limit is: ${filesize(MAX_ASSET_SIZE)}`;
      break;
    }

    const uploadAssetInput: UploadAssetInput = {
      website_id: websiteId,
      file: file,
      product_id: props.product.id,
    };

    try {
      const newAsset = await $mdninja.uploadAsset(uploadAssetInput);
      const updatedProduct = deepClone(props.product);
      updatedProduct.assets!.unshift(newAsset);
      $emit('updated', updatedProduct);
    } catch (err: any) {
      error.value = err.message;
      break;
    }
  }

  loading.value = false;
}

async function deleteAsset(asset: Asset) {
  loading.value = true;
  error.value = '';

  try {
    await $mdninja.deleteAsset(asset.id);
    const updatedProduct = deepClone(props.product);
    updatedProduct.assets = updatedProduct.assets!.filter((a: Asset) => a.id !== asset.id);
    $emit('updated', updatedProduct);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onProductPageCreated(page: ProductPage) {
  showNewProductPageDialog.value = false;
  $router.push(`/websites/${websiteId}/products/${productId}/pages/${page.id}`);
}

async function publishProduct(active: boolean) {
  loading.value = true;
  error.value = '';

  const statusToUpdate = active ? ProductStatus.Active : ProductStatus.Draft;
  const input: UpdateProductInput = {
    id: productId,
    status: statusToUpdate,
  };

  try {
    const updatedProduct = await $mdninja.updateProduct(input);
    status.value = statusToUpdate;
    $emit('updated', updatedProduct);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function openDeleteProductDialog() {
  showDeleteProductDialog.value = true;
}

async function deleteProduct() {
  deleteProductDialogLoading.value = true;
  deleteProductDialogError.value = '';

  const input: DeleteProductInput = {
    id: productId,
  };

  try {
    await $mdninja.deleteProduct(input);
    $router.push(backRoute);
  } catch (err: any) {
    deleteProductDialogError.value = err.message;
  } finally {
    deleteProductDialogLoading.value = false;
  }
}
</script>
