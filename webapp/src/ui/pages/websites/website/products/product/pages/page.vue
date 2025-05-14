<template>
  <div class="w-full">
    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div v-if="page" class="w-full flex flex-col">
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
            <sl-button variant="primary" @click="updatePage" :loading="loading">
                Save
            </sl-button>
          </div>
        </div>

        <div class="flex">
          <Menu as="div" class="relative inline-block text-left">
            <div>
              <MenuButton class="inline-flex w-full justify-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-xs ring-1 ring-inset ring-gray-300 hover:bg-gray-50">
                <EllipsisVerticalIcon class="h-5 w-5 text-gray-700" aria-hidden="true" />
              </MenuButton>
            </div>

            <transition enter-active-class="transition ease-out duration-100" enter-from-class="transform opacity-0 scale-95" enter-to-class="transform opacity-100 scale-100" leave-active-class="transition ease-in duration-75" leave-from-class="transform opacity-100 scale-100" leave-to-class="transform opacity-0 scale-95">
              <MenuItems class="absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-gray-300 focus:outline-none">
                <div class="py-1">
                  <MenuItem v-slot="{ active }">
                    <span @click="openDeletePageDialog"
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Delete Page
                    </span>
                  </MenuItem>
                </div>
              </MenuItems>
            </transition>
          </Menu>
        </div>
      </div>

      <div class="flex flex-col my-4 w-full space-y-4">
        <sl-input :value="title" @input="title = $event.target.value.trim()"
          :disabled="loading" placeholder="How to sell online courses" label="Title"
        />

        <MarkdownEditor label="Content" v-model="bodyMarkdown" />
      </div>

    </div>

  </div>

  <DeleteDialog v-if="page" v-model="showDeletePageDialog" :error="deletePageDialogError"
    :title="deletePageDialogTitle" :message="deletePageDialogMessage" :loading="deletePageDialogLoading"
    @delete="deletePage" />
</template>

<script lang="ts" setup>
import type { ProductPage, UpdateProductPageInput } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRouter } from 'vue-router';
import { useRoute } from 'vue-router';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { useMdninja } from '@/api/mdninja';
import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/vue'
import { EllipsisVerticalIcon } from '@heroicons/vue/24/outline'
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { oneRouteUp } from '@/libs/router_utils';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import { defineAsyncComponent } from 'vue'
const MarkdownEditor = defineAsyncComponent(() =>
  import('@/ui/components/content/markdown_editor.vue')
);
// import MarkdownEditor from '@/ui/components/content/markdown_editor.vue';


// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();
const $router = useRouter();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const pageId = $route.params.page_id as string;
const backRoute = oneRouteUp(oneRouteUp($route.path));
const deletePageDialogTitle = 'Delete Page';
const deletePageDialogMessage = 'Are you sure you want to delete this page? This action cannot be undone.';

let loading = ref(false);
let error = ref('');
let deletePageDialogLoading = ref(false);
let showDeletePageDialog = ref(false);
let deletePageDialogError = ref('');

let page: Ref<ProductPage | null> = ref(null);

let title = ref('');
let bodyMarkdown = ref('');

// computed

// watch

// functions
function resetValues() {
  if (page) {
    title.value = page.value!.title;
    bodyMarkdown.value = page.value!.body_markdown;
  } else {
    title.value = '';
    bodyMarkdown.value = '';
  }
}

async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    page.value = await $mdninja.getProductPage(pageId);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updatePage() {
  loading.value = true;
  error.value = '';

  const input: UpdateProductPageInput = {
    id: pageId,
    title: title.value,
    body_markdown: bodyMarkdown.value,
  };

  try {
    page.value = await $mdninja.updateProductPage(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function openDeletePageDialog() {
  showDeletePageDialog.value = true;
}

async function deletePage() {
  deletePageDialogLoading.value = true;
  deletePageDialogError.value = '';

  try {
    await $mdninja.deleteProductPage(pageId);
    $router.push(backRoute);
  } catch (err: any) {
    deletePageDialogError.value = err.message;
  } finally {
    deletePageDialogLoading.value = false;
  }
}
</script>
