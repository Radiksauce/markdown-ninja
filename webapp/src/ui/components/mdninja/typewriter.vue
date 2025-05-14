<template>
  <div class="container">
    <h1>
      <span class="text-5xl sm:text-7xl typed-text">{{ typeValue }}</span>
      <span class="text-5xl sm:text-7xl blinking-cursor">|</span>
      <span class="text-5xl sm:text-7xl cursor" :class="{ typing: typeStatus }">&nbsp;</span>
    </h1>
  </div>
</template>

<script lang="ts" setup>
import { onMounted, ref } from 'vue';

const eraseTextDelay = 1200;
const newtextDelay = 500;

let typeValue = ref("");
let typeStatus = ref(false);
let displayTextArray = ref(["a Blog", "a Newsletter", "a Website"]);
let typingSpeed = ref(100);
let erasingSpeed = ref(50);
let displayTextArrayIndex = ref(0);
let charIndex = ref(0);

onMounted(() => {
  setTimeout(typeText, 100);
})

function typeText() {
  if (charIndex.value < displayTextArray.value[displayTextArrayIndex.value].length) {
    if (!typeStatus.value) {
      typeStatus.value = true;
    }
    typeValue.value += displayTextArray.value[displayTextArrayIndex.value].charAt(
      charIndex.value
    );
    charIndex.value += 1;
    setTimeout(typeText, typingSpeed.value);
  } else {
    typeStatus.value = false;
    setTimeout(eraseText, eraseTextDelay);
  }
}


function eraseText() {
  if (charIndex.value > 0) {
    if (!typeStatus.value) {
      typeStatus.value = true;
    }
    typeValue.value = displayTextArray.value[displayTextArrayIndex.value].substring(
      0,
      charIndex.value - 1
    );
    charIndex.value -= 1;
    setTimeout(eraseText, erasingSpeed.value);
  } else {
    typeStatus.value = false;
    displayTextArrayIndex.value += 1;
    if (displayTextArrayIndex.value >= displayTextArray.value.length) {
      displayTextArrayIndex.value = 0;
    }
    setTimeout(typeText, newtextDelay);
  }
}
</script>

<style scoped>
.container {
  width: 100%;
  /* height: 100vh; */
  /* display: flex;
  justify-content: center;
  align-items: center; */
}
h1 {
  /* font-size: 6rem; */
  /* font-weight: normal; */
}
/* h1 span.typed-text {
  color: #d2b94b;
} */
.blinking-cursor {
  /* font-size: 6rem; */
  /* color: black; */
  -webkit-animation: 1s blink step-end infinite;
  -moz-animation: 1s blink step-end infinite;
  -ms-animation: 1s blink step-end infinite;
  -o-animation: 1s blink step-end infinite;
  animation: 1s blink step-end infinite;
}
@keyframes blink {
  from, to {
    color: transparent;
  }
  50% {
    color: black;
  }
}
@-moz-keyframes blink {
  from, to {
    color: transparent;
  }
  50% {
    color: black;
  }
}
@-webkit-keyframes blink {
  from, to {
    color: transparent;
  }
  50% {
    color: black;
  }
}
@-ms-keyframes blink {
  from, to {
    color: transparent;
  }
  50% {
    color: black;
  }
}
@-o-keyframes blink {
  from, to {
    color: transparent;
  }
  50% {
    color: black;
  }
}
</style>
