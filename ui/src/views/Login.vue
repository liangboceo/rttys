<template>
  <div class="login-container">
    <div class="layout flex">
      <div class="layout-left"><img src="../assets/login/login.webp" alt="背景图片" /></div>
      <div class="layout-right flex align-center justify-center">
        <div style="width: 100%">
          <div class="title">欢迎{{signup ? $t('Sign up') : $t('Authorization Required')}}{{ applicationName }}</div>
          <div class="form">
            <Form ref="login" :model="formData" :rules="ruleValidate" :label-width="100" label-position="left">
              <FormItem :label="$t('Username')" prop="username">
                <Input v-model="formData.username" prefix="ios-person-outline" :placeholder="$t('Enter username...')" @on-enter="handleSubmit"/>
              </FormItem>
              <FormItem :label="$t('Password')" prop="password">
                <Input type="password" v-model="formData.password" prefix="ios-lock-outline" :placeholder="$t('Enter password...')" password @on-enter="handleSubmit"/>
              </FormItem>
              <FormItem>
                <Button type="primary" size="large" long @click="handleSubmit">{{ signup ? $t('Sign up') : $t('Sign in') }}</Button>
              </FormItem>
            </Form>
            <p v-if="signup" style="text-align: center">{{ $t('Already have an account?') }}<a href="/login" style="text-decoration: none; color: #1c7cd6">{{ $t('Sign in') }}</a></p>
            <p v-else style="text-align: center">{{ $t('New to Rttys?') }}<a href="/login?signup=1" style="text-decoration: none; color: #1c7cd6">{{ $t('Sign up') }}</a></p>
          </div>
        </div>
      </div>
    </div>
  </div>

</template>

<script>
import { GLOUBLE_DATA } from '@/constant/common.js'
export default {
  name: 'Login',
  data() {
    return {
      applicationName:GLOUBLE_DATA.applicationName,
      signup: false,
        formData: {
        username: '',
        password: ''
      },
      ruleValidate: {
        username: [{required: true, trigger: 'blur', message: this.$t('username is required')}],
        password: [{required: true, trigger: 'blur', message: this.$t('password is required')}]
      }
    }
  },
  methods: {
    handleSubmit() {
      (this.$refs['login']).validate(valid => {
        if (valid) {
          const params = {
            username: this.formData.username,
            password: this.formData.password
          };

          if (this.signup) {
            this.axios.post('/signup', params).then(() => {
              this.signup = false;
              this.$router.push('/login');
            }).catch(() => {
              this.$Message.error(this.$t('Sign up Fail.').toString());
            });
          } else {
            this.axios.post('/signin', params).then(res => {
              sessionStorage.setItem('rttys-sid', res.data.sid);
              sessionStorage.setItem('rttys-username', res.data.username);
              sessionStorage.setItem('rttys-admin', res.data.admin);
              this.$router.push('/');
            }).catch(() => {
              this.$Message.error(this.$t('Signin Fail! username or password wrong.').toString());
            });
          }
        }
      });
    }
  },
  created() {
    this.signup = this.$route.query.signup === '1';
    sessionStorage.removeItem('rttys-sid');
  }
}
</script>

<style scoped>
.justify-center {
  justify-content: center;
}
.align-center {
  align-items: center;
}
.flex {
  display: flex;
}

  .login-container {
    width: 100%;
    height: 100%;
    background: url('../assets/login/bg.png') repeat 100% 100%;
    border: 1px solid #fff;
    .layout {
      flex-direction: row;
      height: 80%;
      width: 74%;
      background-color: #fff;
      box-shadow: 0px 6px 30px 0px rgba(0, 0, 0, 0.15);
      margin-top: 5%;
      margin-left: 13%;
    }
  }
  .layout-left {
    position: relative;
    width: 66%;
    height: 100%;
    & > img {
      width: 100%;
      height: 100%;
    }
  }

  .layout-right {
    flex: 1;
    .title {
      text-align: left;
      padding: 0 10%;
      font-size: 28px;
      font-weight: 600;
      color: #333;
      margin-bottom: 30px;
    }
    @media screen and (max-width: 1400px) {
      .title {
        font-size: 26px;
      }
    }
    @media screen and (max-width: 1300px) {
      .title {
        font-size: 24px;
      }
    }
    .form {
      padding: 0 10%;
      min-width: 330px;
      .icon {
        position: absolute;
        transform: translateY(-50%);
        top: 50%;
        left: 12px;
        z-index: 2;
        width: 18px;
        height: 18px;
      }
      .msg {
        font-size: 16px;
        color: #333333;
        margin-bottom: 24px;
      }
    }
  }
  :deep(.login-icon) {
    font-size: 18px;
    margin-right: 10px;
    color: #1F98FF;
  }
</style>
