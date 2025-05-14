<template>
  <sl-dialog :open="model" @sl-request-close="model = false" :label="asset.name">

    <div class="flex max-h-60">
      <!-- <div v-if="asset.type === AssetType.Video" style="position: relative; padding-top: 56.25%;" class="w-full h-full">
        <iframe :src="videoUrl"
            loading="lazy" style="border: none; position: absolute; top: 0; height: 100%; width: 100%;"
            allow="accelerometer; gyroscope; autoplay; encrypted-media; picture-in-picture;" allowfullscreen="true">
        </iframe>
      </div> -->
      <video controls v-if="asset.type === AssetType.Video" style="position: relative;" class="w-full h-full">
        <source :src="assetUrl" />
      </video>

      <img v-else-if="asset.type === AssetType.Image" :alt="asset.name" :src="assetUrl"
        class="rounded w-full object-scale-down max-h-full" />
    </div>

    <!-- <div class="flex-1 mt-5">
      <sl-input label="ID" :value="asset.id" @input="asset.id = $event.target.value" type="text"
          readonly placeholder="Asset ID" />
    </div> -->

    <div class="flex-1 mt-5">
      <sl-input label="Path" :value="path" @input="path = $event.target.value" type="text"
          readonly placeholder="Asset path" />
    </div>

    <!-- <div  v-if="asset.type === AssetType.Video" class="flex-1 mt-5">
      <sl-textarea label="Video iframe code" :value="videoIframeCode" @input="videoIframeCode = $event.target.value"
        rows="8" readonly />
    </div> -->

    <div slot="footer" class="mt-5 flex place-content-end">
      <sl-button outline @click="close()">
        Close
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { computed, type PropType } from 'vue';
import { AssetType, type Asset, type Website } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
// import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const model = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

const props = defineProps({
  website: {
    type: Object as PropType<Website>,
    required: true,
  },
  asset: {
    type: Object as PropType<Asset>,
    required: true,
  },
});

// events
const $emit = defineEmits(['update:modelValue', 'created', 'updated']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables


// computed
const path = computed((): string => `${props.asset.folder}/${props.asset.name}`);
const assetUrl = computed((): string => $mdninja.generateAssetPathUrl(props.website, props.asset));
// const videoUrl = computed((): string => $mdninja.generateVideoUrl(props.website, props.asset));
// const videoIframeCode = computed(() => `<div style="position: relative; padding-top: 56.25%;">
//   <iframe src="${videoUrl.value}"
//     loading="lazy" style="border: none; position: absolute; top: 0; height: 100%; width: 100%;"
//     allow="accelerometer; gyroscope; autoplay; encrypted-media; picture-in-picture;" allowfullscreen="true">
//   </iframe>
// </div>`);

// watch

// functions
function close() {
  model.value = false;
}
</script>
