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

  <PostsList :posts="posts" />
</template>

<script lang="ts" setup>
import { PageType, type PageMetadata } from '@/app/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import PostsList from '@/ui/components/posts_list.vue';
import { useStore } from '@/app/store';
import { listPages, trackPage } from '@/app/mdninja';

// props

// events

// composables
const $store = useStore();

// lifecycle
onBeforeMount(() => {
  document.title = `${website.name} - Blog`;
  trackPage();
  fetchPosts()
});

// variables
const website = $store.website!;
let posts: Ref<PageMetadata[]> = ref([]);

let error = ref('');

// computed

// watch

// functions
async function fetchPosts() {
  // loading.value = true;
  error.value = '';

  try {
    const apiRes = await listPages({ type: PageType.Post });
    posts.value = apiRes.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    $store.setLoading(false);
  }
}
</script>
