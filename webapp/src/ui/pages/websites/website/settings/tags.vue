<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0">
      <h1 class="text-3xl font-extrabold text-gray-900">Tags</h1>
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

    <div v-if="website" class="mt-5">
      <sl-button variant="primary" @click="openNewTagDialog()">
        <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
        New Tag
      </sl-button>

      <TagsList :tags="tags" :website="website"
        @delete="onDeleteTagClicked" @update="onUpdateTagClicked"
      />
    </div>

  </div>

  <TagDialog v-model="showTagDialog" :tag="tagToUpdate" :website-id="websiteId"
    @created="onTagCreated" @updated="onTagUpdated"
  />

  <PDeleteDialog v-model="showDeleteTagDialog" :error="deleteTagDialogError"
    :title="deleteTagDialogTitle" :message="deleteTagDialogMessage" :loading="deleteTagDialogLoading"
    @delete="deleteTag"
  />
</template>

<script lang="ts" setup>
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import TagsList from '@/ui/components/websites/tags_list.vue';
import type { GetTagsInput, GetWebsiteInput, Tag, Website } from '@/api/model';
import PDeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import TagDialog from '@/ui/components/websites/tag_dialog.vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;
const deleteTagDialogTitle = 'Delete Tag';
const deleteTagDialogMessage = 'Are you sure you want to delete this Tag? This action cannot be undone.';

let website: Ref<Website | null> = ref(null);
let tags: Ref<Tag[]> = ref([]);
let loading = ref(false);
let error = ref('');
let tagToUpdate: Ref<Tag | null> = ref(null);
let showTagDialog = ref(false);

let showDeleteTagDialog = ref(false);
let deleteTagDialogError = ref('');
let deleteTagDialogLoading = ref(false);
let tagIdToDelete: Ref<string | null> = ref(null);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const getWebsiteInput: GetWebsiteInput = {
    id: websiteId,
  };
  const getTagsInput: GetTagsInput = {
    website_id: websiteId,
  };

  try {
    const [websiteApi, tagsAPi] = await Promise.all([
      $mdninja.getWebsite(getWebsiteInput),
      $mdninja.fetchTags(getTagsInput),
    ]);

    website.value = websiteApi;
    tags.value = tagsAPi;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function openNewTagDialog() {
  tagToUpdate.value = null;
  showTagDialog.value = true;
}

async function onTagCreated(newTag: Tag) {
  tags.value.push(newTag);
  showTagDialog.value = false;
  tagToUpdate.value = null;
}

async function onTagUpdated(tag: Tag) {
  tags.value = tags.value.map((t: Tag) => {
    if (t.id === tag.id) {
      return tag;
    }
    return t;
  });
  showTagDialog.value = false;
  tagToUpdate.value = null;
}

function onDeleteTagClicked(tag: Tag) {
  tagIdToDelete.value = tag.id;
  showDeleteTagDialog.value = true;
}

function onUpdateTagClicked(tag: Tag) {
  tagToUpdate.value = tag;
  showTagDialog.value = true;
}

async function deleteTag() {
  deleteTagDialogLoading.value = true;
  deleteTagDialogError.value = '';

  try {
    await $mdninja.deleteTag(tagIdToDelete.value!);
    tags.value = tags.value.filter((t: Tag) => t.id !== tagIdToDelete.value);
    tagIdToDelete.value = null;
    showDeleteTagDialog.value = false;
  } catch (err: any) {
    deleteTagDialogError.value = err.message;
  } finally {
    deleteTagDialogLoading.value = false;
  }
}
</script>
