<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Snippets</h1>
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

    <div class="mt-5">
      <sl-button variant="primary" @click="openNewSnippetDialog()">
        <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
        New Snippet
      </sl-button>

      <SnippetsList :snippets="snippets"
        @delete="onDeleteSnippetClicked" @update="onUpdateSnippetClicked"
      />

    </div>

  </div>

  <SnippetDialog v-model="showSnippetDialog" :snippet="snippetToUpdate" :website-id="websiteId"
    @created="snippetCreated" @updated="snippetUpdated"
  />

  <PDeleteDialog v-model="showDeleteSnippetDialog" :error="deleteSnippetDialogError"
    :title="deleteSnippetDialogTitle" :message="deleteSnippetDialogMessage" :loading="deleteSnippetDialogLoading"
    @delete="deleteSnippet"
  />
</template>

<script lang="ts" setup>
import type { ListSnippetsInput, Snippet } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import SnippetsList from '@/ui/components/websites/snippets_list.vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import SnippetDialog from '@/ui/components/websites/snippet_dialog.vue';
import PDeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
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
const deleteSnippetDialogTitle = 'Delete Snippet';
const deleteSnippetDialogMessage = 'Are you sure you want to delete this Snippet? This action cannot be undone.';

let loading = ref(false);
let error = ref('');
let showSnippetDialog = ref(false);
let snippetToUpdate: Ref<Snippet | null> = ref(null);
let showDeleteSnippetDialog = ref(false);
let deleteSnippetDialogError = ref('');
let deleteSnippetDialogLoading = ref(false);
let snippetToDelete: Ref<Snippet | null> = ref(null);
let snippets: Ref<Snippet[]> = ref([]);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: ListSnippetsInput = {
    website_id: websiteId,
  };

  try {
    const res = await $mdninja.listSnippets(input);
    snippets.value = res.data
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function openNewSnippetDialog() {
  snippetToUpdate.value = null;
  showSnippetDialog.value = true;
}

async function snippetCreated(newSnippet: Snippet) {
  snippets.value.push(newSnippet);
  showSnippetDialog.value = false;
  snippetToUpdate.value = null;
}

async function snippetUpdated(snippet: Snippet) {
  snippets.value = snippets.value.map((s: Snippet) => {
    if (s.id === snippet.id) {
      return snippet;
    }
    return s;
  });
  showSnippetDialog.value = false;
  snippetToUpdate.value = null;
}

function onDeleteSnippetClicked(snippet: Snippet) {
  snippetToDelete.value = snippet;
  showDeleteSnippetDialog.value = true;
}

async function deleteSnippet() {
  deleteSnippetDialogLoading.value = true;
  deleteSnippetDialogError.value = '';

  try {
    await $mdninja.deleteSnippet(snippetToDelete.value!.id);
    snippets.value = snippets.value.filter((s: Snippet) => s.id !== snippetToDelete.value!.id);
    snippetToDelete.value = null;
    showDeleteSnippetDialog.value = false;
  } catch (err: any) {
    deleteSnippetDialogError.value = err.message;
  } finally {
    deleteSnippetDialogLoading.value = false;
  }
}

async function onUpdateSnippetClicked(snippet: Snippet) {
  snippetToUpdate.value = snippet;
  showSnippetDialog.value = true;
}
</script>
