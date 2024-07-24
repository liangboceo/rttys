import Vue from 'vue'
import App from './App.vue'
import router from './router'
import axios from 'axios'
import VueAxios from 'vue-axios'
import VueClipboard from 'vue-clipboard2'
import i18n from './plugins/vue-i18n'
import './plugins/view-design'
import './assets/iconfont/iconfont.css'
import { GLOUBLE_DATA } from '@/constant/common.js'
document.title = GLOUBLE_DATA.applicationName
Vue.config.productionTip = false
Vue.use(VueClipboard)
Vue.use(VueAxios, axios);

new Vue({
  router,
  i18n,
  render: h => h(App)
}).$mount('#app')
