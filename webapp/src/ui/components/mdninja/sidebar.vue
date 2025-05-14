<template>
  <!-- desktop sidebar -->
  <aside class="hidden sm:block fixed mt-14 z-0 inset-y-0 w-64 overflow-y-auto border-r border-gray-200 px-5 py-2">
    <slot />
  </aside>

  <!-- mobile sidebar -->
  <sl-drawer ref="mobileSidebar" placement="start" style="--size: 320px;">
    <div slot="label">
      <RouterLink to="/organizations" class="flex flex-shrink-0 items-center">
        <img class="h-8 w-auto" src="/webapp/markdown_ninja_logo.svg" alt="Markdown Ninja logo" />
        <h1 class="text-xl ml-4">
          Markdown Ninja
        </h1>
      </RouterLink>
    </div>

    <slot />
  </sl-drawer>

</template>

<script lang="ts" setup>
import { onBeforeMount, watch, useTemplateRef } from 'vue';
import { useRoute } from 'vue-router';
import SlDrawer from '@shoelace-style/shoelace/dist/components/drawer/drawer.js';


// props
defineExpose({
  open,
});

// events

// composables
const $route = useRoute();

// lifecycle
onBeforeMount(() => close());


// variables
const mobileSidebar = useTemplateRef('mobileSidebar');

// computed

// watch
watch($route, () => close(), { deep: true });

// functions
function open() {
  mobileSidebar?.value?.show();
}

function close() {
  mobileSidebar?.value?.hide();
}
</script>
