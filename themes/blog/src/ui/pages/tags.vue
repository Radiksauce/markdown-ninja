<template>
  <div class="rounded-md bg-red-50 p-2 mb-3 mt-10" v-if="error">
    <div class="flex">
      <div class="ml-3">
        <p class="text-sm text-red-700">
          {{ error }}
        </p>
      </div>
    </div>
  </div>

  <h1 class="my-5">Tags</h1>

  <ul class="px-0 mx-0">
    <li class="flex flex-col" v-for="(tag, $index) in tags">
      <RouterLink :to="tagUrl(tag)" class="py-5 text-xl hover:bg-[#f5f5f5] w-full hover:no-underline px-2.5 flex flex-col sm:flex-row justify-between">
        <span class="flex">{{  tag.name }}</span>
      </RouterLink>
      <hr v-if="$index !== tags.length - 1" />
    </li>
  </ul>
</template>

<script lang="ts" setup>
import { listTags, trackPage } from '@/app/mdninja';
import type { Tag } from '@/app/model';
import { useStore } from '@/app/store';
import { onBeforeMount, ref, type Ref } from 'vue';

// props

// events

// composables
const $store = useStore();

// lifecycle
onBeforeMount(() => {
  document.title = `${website.name} - All Tags`;
  trackPage();
  fetchTags();
});

// variables
const website = $store.website!;
let tags: Ref<Tag[]> = ref([]);

let error = ref('');

// computed

// watch

// functions
async function fetchTags() {
  // loading.value = true;
  error.value = '';

  try {
    const apiRes = await listTags();
    tags.value = apiRes.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    $store.setLoading(false);
  }
}

function tagUrl(tag: Tag) {
  return `/tags/${tag.name}`;
}
</script>
