import anyTest from 'ava';
import browserEnv from 'browser-env';
import * as sinon from 'sinon';
import Strapi from './sdk';
const test = anyTest;
test.beforeEach(t => {
    const strapi = new Strapi('http://strapi-host');
    t.context = {
        axiosRequest: sinon.stub(strapi.axios, 'request').resolves({
            data: {}
        }),
        strapi
    };
});
test('Create an instance', t => {
    t.deepEqual(Object.getOwnPropertyNames(Object.getPrototypeOf(t.context.strapi)), [
        'constructor',
        'request',
        'register',
        'login',
        'forgotPassword',
        'resetPassword',
        'getProviderAuthenticationUrl',
        'authenticateProvider',
        'getEntries',
        'getEntryCount',
        'getEntry',
        'createEntry',
        'updateEntry',
        'deleteEntry',
        'searchFiles',
        'getFiles',
        'getFile',
        'upload',
        'setToken',
        'clearToken',
        'isBrowser'
    ]);
    t.deepEqual(Object.getOwnPropertyNames(t.context.strapi), [
        'axios',
        'storeConfig'
    ]);
    t.deepEqual(t.context.strapi.axios.defaults.baseURL, 'http://strapi-host');
});
test.serial('Create an instance with existing token on localStorage', t => {
    browserEnv(['window']);
    const globalAny = global;
    globalAny.window.localStorage = storageMock();
    const setItem = sinon.spy(globalAny.window.localStorage, 'setItem');
    globalAny.window.localStorage.setItem('jwt', '"XXX"');
    const strapi = new Strapi('http://strapi-host', {
        cookie: false
    });
    t.is(strapi.axios.defaults.headers.common.Authorization, 'Bearer XXX');
    t.true(setItem.calledWith('jwt', '"XXX"'));
    delete strapi.axios.defaults.headers.common.Authorization;
    delete globalAny.window;
});
test('Create an instance with existing token on cookies', t => {
    browserEnv(['window', 'document']);
    const Cookies = require('js-cookie');
    const globalAny = global;
    Cookies.set('jwt', 'XXX');
    // const CookieGet = sinon.spy(Cookies)
    const strapi = new Strapi('http://strapi-host', {
        localStorage: false
    });
    t.is(strapi.axios.defaults.headers.common.Authorization, 'Bearer XXX');
    // TODO: Mock Cookies
    // t.true(CookieGet.calledWith('jwt'));
    delete strapi.axios.defaults.headers.common.Authorization;
    delete globalAny.window;
});
test.serial('Create an instance without token', t => {
    browserEnv(['window']);
    const globalAny = global;
    const strapi = new Strapi('http://strapi-host', {
        cookie: false,
        localStorage: false
    });
    t.is(strapi.axios.defaults.headers.common.Authorization, undefined);
    delete globalAny.window;
});
test('Make a request', async (t) => {
    t.context.axiosRequest.resolves({
        data: [{ foo: 'bar' }]
    });
    const data = await t.context.strapi.request('get', '/foo');
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        url: '/foo'
    }));
    t.deepEqual(data, [{ foo: 'bar' }]);
});
test('Make a request with custom axios config', t => {
    t.context.strapi.request('get', '/foo', {
        headers: {
            foo: 'bar'
        }
    });
    t.true(t.context.axiosRequest.calledWithExactly({
        headers: {
            foo: 'bar'
        },
        method: 'get',
        url: '/foo'
    }));
});
test('Catch a network request', async (t) => {
    t.context.axiosRequest.rejects(new Error('Network Error'));
    await t.throwsAsync(async () => {
        await t.context.strapi.request('get', '/foo');
    }, { message: 'Network Error' });
});
test('Catch a request', async (t) => {
    t.context.axiosRequest.rejects({
        response: {
            data: {
                message: 'error'
            }
        }
    });
    await t.throwsAsync(async () => {
        await t.context.strapi.request('get', '/foo');
    }, { message: 'error' });
});
test('Register', async (t) => {
    t.context.axiosRequest.resolves({
        data: {
            jwt: 'foo',
            user: {}
        }
    });
    const authentication = await t.context.strapi.register('username', 'foo@bar.com', 'password', 'foo', 'bar', 'Foobar co', 'yes');
    t.true(t.context.axiosRequest.calledWithExactly({
        data: {
            email: 'foo@bar.com',
            password: 'password',
            username: 'username',
            firstname: 'foo',
            lastname: 'bar',
            company: 'Foobar co',
            optin: 'yes'
        },
        method: 'post',
        url: '/auth/local/register'
    }));
    t.deepEqual(authentication, {
        jwt: 'foo',
        user: {}
    });
});
test('Login', async (t) => {
    t.context.axiosRequest.resolves({
        data: {
            jwt: 'foo',
            user: {}
        }
    });
    const authentication = await t.context.strapi.login('identifier', 'password');
    t.true(t.context.axiosRequest.calledWithExactly({
        data: {
            identifier: 'identifier',
            password: 'password'
        },
        method: 'post',
        url: '/auth/local'
    }));
    t.deepEqual(authentication, {
        jwt: 'foo',
        user: {}
    });
});
test.serial('Set Authorization header on axios', async (t) => {
    t.is(t.context.strapi.axios.defaults.headers.common.Authorization, undefined);
    const setToken = sinon.spy(t.context.strapi, 'setToken');
    t.context.axiosRequest.resolves({
        data: {
            jwt: 'foo',
            user: {}
        }
    });
    const authentication = await t.context.strapi.login('identifier', 'password');
    t.true(setToken.calledWithExactly(authentication.jwt));
    t.is(t.context.strapi.axios.defaults.headers.common.Authorization, 'Bearer foo');
});
test('Forgot password', async (t) => {
    await t.context.strapi.forgotPassword('foo@bar.com', 'https://my-domain.com/reset-password');
    t.true(t.context.axiosRequest.calledWithExactly({
        data: {
            email: 'foo@bar.com',
            url: 'https://my-domain.com/reset-password'
        },
        method: 'post',
        url: '/auth/forgot-password'
    }));
});
test('Reset password', async (t) => {
    await t.context.strapi.resetPassword('code', 'password', 'confirm');
    t.true(t.context.axiosRequest.calledWithExactly({
        data: {
            code: 'code',
            password: 'password',
            passwordConfirmation: 'confirm'
        },
        method: 'post',
        url: '/auth/reset-password'
    }));
});
test('Provider authentication url', t => {
    t.is(t.context.strapi.getProviderAuthenticationUrl('facebook'), 'http://strapi-host/connect/facebook');
});
test('Provider authentication on Node.js', async (t) => {
    t.context.axiosRequest.resolves({
        data: {
            jwt: 'foo',
            user: {}
        }
    });
    const authentication = await t.context.strapi.authenticateProvider('facebook', {
        code: 'XXX'
    });
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        params: {
            code: 'XXX'
        },
        url: '/auth/facebook/callback'
    }));
    t.deepEqual(authentication, {
        jwt: 'foo',
        user: {}
    });
});
test.serial('Provider authentication on browser', async (t) => {
    browserEnv(['window'], {
        url: 'http://localhost?access_token=XXX'
    });
    const globalAny = global;
    globalAny.window.localStorage = storageMock();
    t.context.axiosRequest.resolves({
        data: {
            jwt: 'foo',
            user: {}
        }
    });
    const authentication = await t.context.strapi.authenticateProvider('github');
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        params: {
            access_token: 'XXX'
        },
        url: '/auth/github/callback'
    }));
    t.deepEqual(authentication, {
        jwt: 'foo',
        user: {}
    });
    delete globalAny.window;
});
test('Get entries', async (t) => {
    await t.context.strapi.getEntries('user', {
        _sort: 'email:asc'
    });
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        params: {
            _sort: 'email:asc'
        },
        url: '/user'
    }));
});
test('Get entry count', async (t) => {
    await t.context.strapi.getEntryCount('user', {
        name_contains: 'jack'
    });
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        params: {
            name_contains: 'jack'
        },
        url: '/user/count'
    }));
});
test('Get entry', async (t) => {
    await t.context.strapi.getEntry('user', 'ID');
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        url: '/user/ID'
    }));
});
test('Create entry', async (t) => {
    await t.context.strapi.createEntry('user', {
        foo: 'bar'
    });
    t.true(t.context.axiosRequest.calledWithExactly({
        data: {
            foo: 'bar'
        },
        method: 'post',
        url: '/user'
    }));
});
test('Update entry', async (t) => {
    await t.context.strapi.updateEntry('user', 'ID', {
        foo: 'bar'
    });
    t.true(t.context.axiosRequest.calledWithExactly({
        data: {
            foo: 'bar'
        },
        method: 'put',
        url: '/user/ID'
    }));
});
test('Delete entry', async (t) => {
    await t.context.strapi.deleteEntry('user', 'ID');
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'delete',
        url: '/user/ID'
    }));
});
test('Search files', async (t) => {
    await t.context.strapi.searchFiles('foo');
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        url: '/upload/search/foo'
    }));
});
test('Get files', async (t) => {
    await t.context.strapi.getFiles({
        _sort: 'size:asc'
    });
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        params: {
            _sort: 'size:asc'
        },
        url: '/upload/files'
    }));
});
test('Get file', async (t) => {
    await t.context.strapi.getFile('ID');
    t.true(t.context.axiosRequest.calledWithExactly({
        method: 'get',
        url: '/upload/files/ID'
    }));
});
test('Upload file on Node.js', async (t) => {
    const FormData = require('form-data');
    const form = new FormData();
    form.append('files', 'foo', 'file-name.ext');
    await t.context.strapi.upload(form);
    t.true(t.context.axiosRequest.calledWithExactly({
        data: form,
        method: 'post',
        url: '/upload'
    }));
});
test.serial('Upload file on Browser', async (t) => {
    browserEnv(['window']);
    const globalAny = global;
    const form = new globalAny.window.FormData();
    form.append('files', new globalAny.window.Blob(['foo'], { type: 'text/plain' }), 'file-name.ext');
    await t.context.strapi.upload(form);
    t.true(t.context.axiosRequest.calledWithExactly({
        data: form,
        method: 'post',
        url: '/upload'
    }));
    delete globalAny.window;
});
test('Set token', t => {
    t.is(t.context.strapi.axios.defaults.headers.common.Authorization, undefined);
    t.context.strapi.setToken('foo');
    t.is(t.context.strapi.axios.defaults.headers.common.Authorization, 'Bearer foo');
});
test('Set token on Node.js', t => {
    browserEnv(['window', 'document']);
    // const Cookies = require('js-cookie');
    const globalAny = global;
    globalAny.window.localStorage = storageMock();
    const setItem = sinon.spy(globalAny.window.localStorage, 'setItem');
    // const CookieSet = sinon.spy(Cookies, 'set')
    const strapi = new Strapi('http://strapi-host', {
        cookie: false,
        localStorage: false
    });
    strapi.setToken('XXX');
    t.is(strapi.axios.defaults.headers.common.Authorization, 'Bearer XXX');
    t.true(setItem.notCalled);
    // t.true(CookieSet.notCalled)
    delete globalAny.window;
});
test('Clear token without storage', t => {
    browserEnv(['window']);
    const globalAny = global;
    globalAny.window.localStorage = storageMock();
    const setItem = sinon.spy(globalAny.window.localStorage, 'setItem');
    const strapi = new Strapi('http://strapi-host', {
        cookie: false,
        localStorage: false
    });
    strapi.axios.defaults.headers.common.Authorization = 'Bearer XXX';
    strapi.clearToken();
    t.true(setItem.notCalled);
    t.is(strapi.axios.defaults.headers.common.Authorization, undefined);
});
function storageMock() {
    const storage = {};
    return {
        setItem(key, value) {
            storage[key] = value || '';
        },
        getItem(key) {
            return key in storage ? storage[key] : null;
        },
        removeItem(key) {
            delete storage[key];
        }
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2RrLnNwZWMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbGliL3Nkay5zcGVjLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE9BQU8sT0FBMEIsTUFBTSxLQUFLLENBQUM7QUFDN0MsT0FBTyxVQUFVLE1BQU0sYUFBYSxDQUFDO0FBQ3JDLE9BQU8sS0FBSyxLQUFLLE1BQU0sT0FBTyxDQUFDO0FBQy9CLE9BQU8sTUFBTSxNQUFNLE9BQU8sQ0FBQztBQUUzQixNQUFNLElBQUksR0FBRyxPQUdYLENBQUM7QUFFSCxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxFQUFFO0lBQ2xCLE1BQU0sTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLG9CQUFvQixDQUFDLENBQUM7SUFDaEQsQ0FBQyxDQUFDLE9BQU8sR0FBRztRQUNWLFlBQVksRUFBRSxLQUFLLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUMsUUFBUSxDQUFDO1lBQ3pELElBQUksRUFBRSxFQUFFO1NBQ1QsQ0FBQztRQUNGLE1BQU07S0FDUCxDQUFDO0FBQ0osQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsb0JBQW9CLEVBQUUsQ0FBQyxDQUFDLEVBQUU7SUFDN0IsQ0FBQyxDQUFDLFNBQVMsQ0FDVCxNQUFNLENBQUMsbUJBQW1CLENBQUMsTUFBTSxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQ25FO1FBQ0UsYUFBYTtRQUNiLFNBQVM7UUFDVCxVQUFVO1FBQ1YsT0FBTztRQUNQLGdCQUFnQjtRQUNoQixlQUFlO1FBQ2YsOEJBQThCO1FBQzlCLHNCQUFzQjtRQUN0QixZQUFZO1FBQ1osZUFBZTtRQUNmLFVBQVU7UUFDVixhQUFhO1FBQ2IsYUFBYTtRQUNiLGFBQWE7UUFDYixhQUFhO1FBQ2IsVUFBVTtRQUNWLFNBQVM7UUFDVCxRQUFRO1FBQ1IsVUFBVTtRQUNWLFlBQVk7UUFDWixXQUFXO0tBQ1osQ0FDRixDQUFDO0lBRUYsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsbUJBQW1CLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsRUFBRTtRQUN4RCxPQUFPO1FBQ1AsYUFBYTtLQUNkLENBQUMsQ0FBQztJQUVILENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxPQUFPLEVBQUUsb0JBQW9CLENBQUMsQ0FBQztBQUM3RSxDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyxNQUFNLENBQUMsd0RBQXdELEVBQUUsQ0FBQyxDQUFDLEVBQUU7SUFDeEUsVUFBVSxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQztJQUN2QixNQUFNLFNBQVMsR0FBUSxNQUFNLENBQUM7SUFDOUIsU0FBUyxDQUFDLE1BQU0sQ0FBQyxZQUFZLEdBQUcsV0FBVyxFQUFFLENBQUM7SUFDOUMsTUFBTSxPQUFPLEdBQUcsS0FBSyxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFDLFlBQVksRUFBRSxTQUFTLENBQUMsQ0FBQztJQUNwRSxTQUFTLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLE9BQU8sQ0FBQyxDQUFDO0lBQ3RELE1BQU0sTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLG9CQUFvQixFQUFFO1FBQzlDLE1BQU0sRUFBRSxLQUFLO0tBQ2QsQ0FBQyxDQUFDO0lBRUgsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxZQUFZLENBQUMsQ0FBQztJQUN2RSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsS0FBSyxFQUFFLE9BQU8sQ0FBQyxDQUFDLENBQUM7SUFDM0MsT0FBTyxNQUFNLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLGFBQWEsQ0FBQztJQUMxRCxPQUFPLFNBQVMsQ0FBQyxNQUFNLENBQUM7QUFDMUIsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsbURBQW1ELEVBQUUsQ0FBQyxDQUFDLEVBQUU7SUFDNUQsVUFBVSxDQUFDLENBQUMsUUFBUSxFQUFFLFVBQVUsQ0FBQyxDQUFDLENBQUM7SUFDbkMsTUFBTSxPQUFPLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDO0lBQ3JDLE1BQU0sU0FBUyxHQUFRLE1BQU0sQ0FBQztJQUM5QixPQUFPLENBQUMsR0FBRyxDQUFDLEtBQUssRUFBRSxLQUFLLENBQUMsQ0FBQztJQUMxQix1Q0FBdUM7SUFFdkMsTUFBTSxNQUFNLEdBQUcsSUFBSSxNQUFNLENBQUMsb0JBQW9CLEVBQUU7UUFDOUMsWUFBWSxFQUFFLEtBQUs7S0FDcEIsQ0FBQyxDQUFDO0lBRUgsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxZQUFZLENBQUMsQ0FBQztJQUN2RSxxQkFBcUI7SUFDckIsdUNBQXVDO0lBQ3ZDLE9BQU8sTUFBTSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUM7SUFDMUQsT0FBTyxTQUFTLENBQUMsTUFBTSxDQUFDO0FBQzFCLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLE1BQU0sQ0FBQyxrQ0FBa0MsRUFBRSxDQUFDLENBQUMsRUFBRTtJQUNsRCxVQUFVLENBQUMsQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDO0lBQ3ZCLE1BQU0sU0FBUyxHQUFRLE1BQU0sQ0FBQztJQUM5QixNQUFNLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxvQkFBb0IsRUFBRTtRQUM5QyxNQUFNLEVBQUUsS0FBSztRQUNiLFlBQVksRUFBRSxLQUFLO0tBQ3BCLENBQUMsQ0FBQztJQUVILENBQUMsQ0FBQyxFQUFFLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxhQUFhLEVBQUUsU0FBUyxDQUFDLENBQUM7SUFDcEUsT0FBTyxTQUFTLENBQUMsTUFBTSxDQUFDO0FBQzFCLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLGdCQUFnQixFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUMvQixDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUM7UUFDOUIsSUFBSSxFQUFFLENBQUMsRUFBRSxHQUFHLEVBQUUsS0FBSyxFQUFFLENBQUM7S0FDdkIsQ0FBQyxDQUFDO0lBQ0gsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBRTNELENBQUMsQ0FBQyxJQUFJLENBQ0osQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsaUJBQWlCLENBQUM7UUFDdkMsTUFBTSxFQUFFLEtBQUs7UUFDYixHQUFHLEVBQUUsTUFBTTtLQUNaLENBQUMsQ0FDSCxDQUFDO0lBQ0YsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxJQUFJLEVBQUUsQ0FBQyxFQUFFLEdBQUcsRUFBRSxLQUFLLEVBQUUsQ0FBQyxDQUFDLENBQUM7QUFDdEMsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMseUNBQXlDLEVBQUUsQ0FBQyxDQUFDLEVBQUU7SUFDbEQsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxNQUFNLEVBQUU7UUFDdEMsT0FBTyxFQUFFO1lBQ1AsR0FBRyxFQUFFLEtBQUs7U0FDWDtLQUNGLENBQUMsQ0FBQztJQUVILENBQUMsQ0FBQyxJQUFJLENBQ0osQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsaUJBQWlCLENBQUM7UUFDdkMsT0FBTyxFQUFFO1lBQ1AsR0FBRyxFQUFFLEtBQUs7U0FDWDtRQUNELE1BQU0sRUFBRSxLQUFLO1FBQ2IsR0FBRyxFQUFFLE1BQU07S0FDWixDQUFDLENBQ0gsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLHlCQUF5QixFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUN4QyxDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxPQUFPLENBQUMsSUFBSSxLQUFLLENBQUMsZUFBZSxDQUFDLENBQUMsQ0FBQztJQUUzRCxNQUFNLENBQUMsQ0FBQyxXQUFXLENBQ2pCLEtBQUssSUFBSSxFQUFFO1FBQ1QsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ2hELENBQUMsRUFDRCxFQUFFLE9BQU8sRUFBRSxlQUFlLEVBQUUsQ0FDN0IsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLGlCQUFpQixFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUNoQyxDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxPQUFPLENBQUM7UUFDN0IsUUFBUSxFQUFFO1lBQ1IsSUFBSSxFQUFFO2dCQUNKLE9BQU8sRUFBRSxPQUFPO2FBQ2pCO1NBQ0Y7S0FDRixDQUFDLENBQUM7SUFFSCxNQUFNLENBQUMsQ0FBQyxXQUFXLENBQ2pCLEtBQUssSUFBSSxFQUFFO1FBQ1QsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ2hELENBQUMsRUFDRCxFQUFFLE9BQU8sRUFBRSxPQUFPLEVBQUUsQ0FDckIsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLFVBQVUsRUFBRSxLQUFLLEVBQUMsQ0FBQyxFQUFDLEVBQUU7SUFDekIsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDO1FBQzlCLElBQUksRUFBRTtZQUNKLEdBQUcsRUFBRSxLQUFLO1lBQ1YsSUFBSSxFQUFFLEVBQUU7U0FDVDtLQUNGLENBQUMsQ0FBQztJQUNILE1BQU0sY0FBYyxHQUFHLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUNwRCxVQUFVLEVBQ1YsYUFBYSxFQUNiLFVBQVUsRUFDVixLQUFLLEVBQ0wsS0FBSyxFQUNMLFdBQVcsRUFDWCxLQUFLLENBQ04sQ0FBQztJQUVGLENBQUMsQ0FBQyxJQUFJLENBQ0osQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsaUJBQWlCLENBQUM7UUFDdkMsSUFBSSxFQUFFO1lBQ0osS0FBSyxFQUFFLGFBQWE7WUFDcEIsUUFBUSxFQUFFLFVBQVU7WUFDcEIsUUFBUSxFQUFFLFVBQVU7WUFDcEIsU0FBUyxFQUFFLEtBQUs7WUFDaEIsUUFBUSxFQUFFLEtBQUs7WUFDZixPQUFPLEVBQUUsV0FBVztZQUNwQixLQUFLLEVBQUUsS0FBSztTQUNiO1FBQ0QsTUFBTSxFQUFFLE1BQU07UUFDZCxHQUFHLEVBQUUsc0JBQXNCO0tBQzVCLENBQUMsQ0FDSCxDQUFDO0lBQ0YsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxjQUFjLEVBQUU7UUFDMUIsR0FBRyxFQUFFLEtBQUs7UUFDVixJQUFJLEVBQUUsRUFBRTtLQUNULENBQUMsQ0FBQztBQUNMLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLE9BQU8sRUFBRSxLQUFLLEVBQUMsQ0FBQyxFQUFDLEVBQUU7SUFDdEIsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDO1FBQzlCLElBQUksRUFBRTtZQUNKLEdBQUcsRUFBRSxLQUFLO1lBQ1YsSUFBSSxFQUFFLEVBQUU7U0FDVDtLQUNGLENBQUMsQ0FBQztJQUNILE1BQU0sY0FBYyxHQUFHLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLFlBQVksRUFBRSxVQUFVLENBQUMsQ0FBQztJQUU5RSxDQUFDLENBQUMsSUFBSSxDQUNKLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLGlCQUFpQixDQUFDO1FBQ3ZDLElBQUksRUFBRTtZQUNKLFVBQVUsRUFBRSxZQUFZO1lBQ3hCLFFBQVEsRUFBRSxVQUFVO1NBQ3JCO1FBQ0QsTUFBTSxFQUFFLE1BQU07UUFDZCxHQUFHLEVBQUUsYUFBYTtLQUNuQixDQUFDLENBQ0gsQ0FBQztJQUNGLENBQUMsQ0FBQyxTQUFTLENBQUMsY0FBYyxFQUFFO1FBQzFCLEdBQUcsRUFBRSxLQUFLO1FBQ1YsSUFBSSxFQUFFLEVBQUU7S0FDVCxDQUFDLENBQUM7QUFDTCxDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyxNQUFNLENBQUMsbUNBQW1DLEVBQUUsS0FBSyxFQUFDLENBQUMsRUFBQyxFQUFFO0lBQ3pELENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxTQUFTLENBQUMsQ0FBQztJQUM5RSxNQUFNLFFBQVEsR0FBRyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxFQUFFLFVBQVUsQ0FBQyxDQUFDO0lBQ3pELENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQztRQUM5QixJQUFJLEVBQUU7WUFDSixHQUFHLEVBQUUsS0FBSztZQUNWLElBQUksRUFBRSxFQUFFO1NBQ1Q7S0FDRixDQUFDLENBQUM7SUFDSCxNQUFNLGNBQWMsR0FBRyxNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxZQUFZLEVBQUUsVUFBVSxDQUFDLENBQUM7SUFFOUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsaUJBQWlCLENBQUMsY0FBYyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7SUFDdkQsQ0FBQyxDQUFDLEVBQUUsQ0FDRixDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUM1RCxZQUFZLENBQ2IsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLGlCQUFpQixFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUNoQyxNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLGNBQWMsQ0FDbkMsYUFBYSxFQUNiLHNDQUFzQyxDQUN2QyxDQUFDO0lBRUYsQ0FBQyxDQUFDLElBQUksQ0FDSixDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxpQkFBaUIsQ0FBQztRQUN2QyxJQUFJLEVBQUU7WUFDSixLQUFLLEVBQUUsYUFBYTtZQUNwQixHQUFHLEVBQUUsc0NBQXNDO1NBQzVDO1FBQ0QsTUFBTSxFQUFFLE1BQU07UUFDZCxHQUFHLEVBQUUsdUJBQXVCO0tBQzdCLENBQUMsQ0FDSCxDQUFDO0FBQ0osQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsZ0JBQWdCLEVBQUUsS0FBSyxFQUFDLENBQUMsRUFBQyxFQUFFO0lBQy9CLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsYUFBYSxDQUFDLE1BQU0sRUFBRSxVQUFVLEVBQUUsU0FBUyxDQUFDLENBQUM7SUFFcEUsQ0FBQyxDQUFDLElBQUksQ0FDSixDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxpQkFBaUIsQ0FBQztRQUN2QyxJQUFJLEVBQUU7WUFDSixJQUFJLEVBQUUsTUFBTTtZQUNaLFFBQVEsRUFBRSxVQUFVO1lBQ3BCLG9CQUFvQixFQUFFLFNBQVM7U0FDaEM7UUFDRCxNQUFNLEVBQUUsTUFBTTtRQUNkLEdBQUcsRUFBRSxzQkFBc0I7S0FDNUIsQ0FBQyxDQUNILENBQUM7QUFDSixDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyw2QkFBNkIsRUFBRSxDQUFDLENBQUMsRUFBRTtJQUN0QyxDQUFDLENBQUMsRUFBRSxDQUNGLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLDRCQUE0QixDQUFDLFVBQVUsQ0FBQyxFQUN6RCxxQ0FBcUMsQ0FDdEMsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLG9DQUFvQyxFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUNuRCxDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUM7UUFDOUIsSUFBSSxFQUFFO1lBQ0osR0FBRyxFQUFFLEtBQUs7WUFDVixJQUFJLEVBQUUsRUFBRTtTQUNUO0tBQ0YsQ0FBQyxDQUFDO0lBQ0gsTUFBTSxjQUFjLEdBQUcsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxvQkFBb0IsQ0FDaEUsVUFBVSxFQUNWO1FBQ0UsSUFBSSxFQUFFLEtBQUs7S0FDWixDQUNGLENBQUM7SUFFRixDQUFDLENBQUMsSUFBSSxDQUNKLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLGlCQUFpQixDQUFDO1FBQ3ZDLE1BQU0sRUFBRSxLQUFLO1FBQ2IsTUFBTSxFQUFFO1lBQ04sSUFBSSxFQUFFLEtBQUs7U0FDWjtRQUNELEdBQUcsRUFBRSx5QkFBeUI7S0FDL0IsQ0FBQyxDQUNILENBQUM7SUFDRixDQUFDLENBQUMsU0FBUyxDQUFDLGNBQWMsRUFBRTtRQUMxQixHQUFHLEVBQUUsS0FBSztRQUNWLElBQUksRUFBRSxFQUFFO0tBQ1QsQ0FBQyxDQUFDO0FBQ0wsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsTUFBTSxDQUFDLG9DQUFvQyxFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUMxRCxVQUFVLENBQUMsQ0FBQyxRQUFRLENBQUMsRUFBRTtRQUNyQixHQUFHLEVBQUUsbUNBQW1DO0tBQ3pDLENBQUMsQ0FBQztJQUNILE1BQU0sU0FBUyxHQUFRLE1BQU0sQ0FBQztJQUM5QixTQUFTLENBQUMsTUFBTSxDQUFDLFlBQVksR0FBRyxXQUFXLEVBQUUsQ0FBQztJQUM5QyxDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUM7UUFDOUIsSUFBSSxFQUFFO1lBQ0osR0FBRyxFQUFFLEtBQUs7WUFDVixJQUFJLEVBQUUsRUFBRTtTQUNUO0tBQ0YsQ0FBQyxDQUFDO0lBQ0gsTUFBTSxjQUFjLEdBQUcsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxvQkFBb0IsQ0FBQyxRQUFRLENBQUMsQ0FBQztJQUU3RSxDQUFDLENBQUMsSUFBSSxDQUNKLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLGlCQUFpQixDQUFDO1FBQ3ZDLE1BQU0sRUFBRSxLQUFLO1FBQ2IsTUFBTSxFQUFFO1lBQ04sWUFBWSxFQUFFLEtBQUs7U0FDcEI7UUFDRCxHQUFHLEVBQUUsdUJBQXVCO0tBQzdCLENBQUMsQ0FDSCxDQUFDO0lBQ0YsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxjQUFjLEVBQUU7UUFDMUIsR0FBRyxFQUFFLEtBQUs7UUFDVixJQUFJLEVBQUUsRUFBRTtLQUNULENBQUMsQ0FBQztJQUNILE9BQU8sU0FBUyxDQUFDLE1BQU0sQ0FBQztBQUMxQixDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyxhQUFhLEVBQUUsS0FBSyxFQUFDLENBQUMsRUFBQyxFQUFFO0lBQzVCLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFDLE1BQU0sRUFBRTtRQUN4QyxLQUFLLEVBQUUsV0FBVztLQUNuQixDQUFDLENBQUM7SUFFSCxDQUFDLENBQUMsSUFBSSxDQUNKLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLGlCQUFpQixDQUFDO1FBQ3ZDLE1BQU0sRUFBRSxLQUFLO1FBQ2IsTUFBTSxFQUFFO1lBQ04sS0FBSyxFQUFFLFdBQVc7U0FDbkI7UUFDRCxHQUFHLEVBQUUsT0FBTztLQUNiLENBQUMsQ0FDSCxDQUFDO0FBQ0osQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsaUJBQWlCLEVBQUUsS0FBSyxFQUFDLENBQUMsRUFBQyxFQUFFO0lBQ2hDLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsYUFBYSxDQUFDLE1BQU0sRUFBRTtRQUMzQyxhQUFhLEVBQUUsTUFBTTtLQUN0QixDQUFDLENBQUM7SUFFSCxDQUFDLENBQUMsSUFBSSxDQUNKLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLGlCQUFpQixDQUFDO1FBQ3ZDLE1BQU0sRUFBRSxLQUFLO1FBQ2IsTUFBTSxFQUFFO1lBQ04sYUFBYSxFQUFFLE1BQU07U0FDdEI7UUFDRCxHQUFHLEVBQUUsYUFBYTtLQUNuQixDQUFDLENBQ0gsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLFdBQVcsRUFBRSxLQUFLLEVBQUMsQ0FBQyxFQUFDLEVBQUU7SUFDMUIsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsTUFBTSxFQUFFLElBQUksQ0FBQyxDQUFDO0lBRTlDLENBQUMsQ0FBQyxJQUFJLENBQ0osQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsaUJBQWlCLENBQUM7UUFDdkMsTUFBTSxFQUFFLEtBQUs7UUFDYixHQUFHLEVBQUUsVUFBVTtLQUNoQixDQUFDLENBQ0gsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLGNBQWMsRUFBRSxLQUFLLEVBQUMsQ0FBQyxFQUFDLEVBQUU7SUFDN0IsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsTUFBTSxFQUFFO1FBQ3pDLEdBQUcsRUFBRSxLQUFLO0tBQ1gsQ0FBQyxDQUFDO0lBRUgsQ0FBQyxDQUFDLElBQUksQ0FDSixDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxpQkFBaUIsQ0FBQztRQUN2QyxJQUFJLEVBQUU7WUFDSixHQUFHLEVBQUUsS0FBSztTQUNYO1FBQ0QsTUFBTSxFQUFFLE1BQU07UUFDZCxHQUFHLEVBQUUsT0FBTztLQUNiLENBQUMsQ0FDSCxDQUFDO0FBQ0osQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsY0FBYyxFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUM3QixNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxNQUFNLEVBQUUsSUFBSSxFQUFFO1FBQy9DLEdBQUcsRUFBRSxLQUFLO0tBQ1gsQ0FBQyxDQUFDO0lBRUgsQ0FBQyxDQUFDLElBQUksQ0FDSixDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxpQkFBaUIsQ0FBQztRQUN2QyxJQUFJLEVBQUU7WUFDSixHQUFHLEVBQUUsS0FBSztTQUNYO1FBQ0QsTUFBTSxFQUFFLEtBQUs7UUFDYixHQUFHLEVBQUUsVUFBVTtLQUNoQixDQUFDLENBQ0gsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLGNBQWMsRUFBRSxLQUFLLEVBQUMsQ0FBQyxFQUFDLEVBQUU7SUFDN0IsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsTUFBTSxFQUFFLElBQUksQ0FBQyxDQUFDO0lBRWpELENBQUMsQ0FBQyxJQUFJLENBQ0osQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsaUJBQWlCLENBQUM7UUFDdkMsTUFBTSxFQUFFLFFBQVE7UUFDaEIsR0FBRyxFQUFFLFVBQVU7S0FDaEIsQ0FBQyxDQUNILENBQUM7QUFDSixDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyxjQUFjLEVBQUUsS0FBSyxFQUFDLENBQUMsRUFBQyxFQUFFO0lBQzdCLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBRTFDLENBQUMsQ0FBQyxJQUFJLENBQ0osQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsaUJBQWlCLENBQUM7UUFDdkMsTUFBTSxFQUFFLEtBQUs7UUFDYixHQUFHLEVBQUUsb0JBQW9CO0tBQzFCLENBQUMsQ0FDSCxDQUFDO0FBQ0osQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsV0FBVyxFQUFFLEtBQUssRUFBQyxDQUFDLEVBQUMsRUFBRTtJQUMxQixNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQztRQUM5QixLQUFLLEVBQUUsVUFBVTtLQUNsQixDQUFDLENBQUM7SUFFSCxDQUFDLENBQUMsSUFBSSxDQUNKLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLGlCQUFpQixDQUFDO1FBQ3ZDLE1BQU0sRUFBRSxLQUFLO1FBQ2IsTUFBTSxFQUFFO1lBQ04sS0FBSyxFQUFFLFVBQVU7U0FDbEI7UUFDRCxHQUFHLEVBQUUsZUFBZTtLQUNyQixDQUFDLENBQ0gsQ0FBQztBQUNKLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLFVBQVUsRUFBRSxLQUFLLEVBQUMsQ0FBQyxFQUFDLEVBQUU7SUFDekIsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUM7SUFFckMsQ0FBQyxDQUFDLElBQUksQ0FDSixDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxpQkFBaUIsQ0FBQztRQUN2QyxNQUFNLEVBQUUsS0FBSztRQUNiLEdBQUcsRUFBRSxrQkFBa0I7S0FDeEIsQ0FBQyxDQUNILENBQUM7QUFDSixDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyx3QkFBd0IsRUFBRSxLQUFLLEVBQUMsQ0FBQyxFQUFDLEVBQUU7SUFDdkMsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDO0lBQ3RDLE1BQU0sSUFBSSxHQUFHLElBQUksUUFBUSxFQUFFLENBQUM7SUFDNUIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsS0FBSyxFQUFFLGVBQWUsQ0FBQyxDQUFDO0lBQzdDLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDO0lBRXBDLENBQUMsQ0FBQyxJQUFJLENBQ0osQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsaUJBQWlCLENBQUM7UUFDdkMsSUFBSSxFQUFFLElBQUk7UUFDVixNQUFNLEVBQUUsTUFBTTtRQUNkLEdBQUcsRUFBRSxTQUFTO0tBQ2YsQ0FBQyxDQUNILENBQUM7QUFDSixDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyxNQUFNLENBQUMsd0JBQXdCLEVBQUUsS0FBSyxFQUFDLENBQUMsRUFBQyxFQUFFO0lBQzlDLFVBQVUsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUM7SUFDdkIsTUFBTSxTQUFTLEdBQVEsTUFBTSxDQUFDO0lBQzlCLE1BQU0sSUFBSSxHQUFHLElBQUksU0FBUyxDQUFDLE1BQU0sQ0FBQyxRQUFRLEVBQUUsQ0FBQztJQUM3QyxJQUFJLENBQUMsTUFBTSxDQUNULE9BQU8sRUFDUCxJQUFJLFNBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUMsS0FBSyxDQUFDLEVBQUUsRUFBRSxJQUFJLEVBQUUsWUFBWSxFQUFFLENBQUMsRUFDMUQsZUFBZSxDQUNoQixDQUFDO0lBQ0YsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUM7SUFFcEMsQ0FBQyxDQUFDLElBQUksQ0FDSixDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxpQkFBaUIsQ0FBQztRQUN2QyxJQUFJLEVBQUUsSUFBSTtRQUNWLE1BQU0sRUFBRSxNQUFNO1FBQ2QsR0FBRyxFQUFFLFNBQVM7S0FDZixDQUFDLENBQ0gsQ0FBQztJQUNGLE9BQU8sU0FBUyxDQUFDLE1BQU0sQ0FBQztBQUMxQixDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyxXQUFXLEVBQUUsQ0FBQyxDQUFDLEVBQUU7SUFDcEIsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUFFLFNBQVMsQ0FBQyxDQUFDO0lBQzlFLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUNqQyxDQUFDLENBQUMsRUFBRSxDQUNGLENBQUMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxhQUFhLEVBQzVELFlBQVksQ0FDYixDQUFDO0FBQ0osQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsc0JBQXNCLEVBQUUsQ0FBQyxDQUFDLEVBQUU7SUFDL0IsVUFBVSxDQUFDLENBQUMsUUFBUSxFQUFFLFVBQVUsQ0FBQyxDQUFDLENBQUM7SUFDbkMsd0NBQXdDO0lBQ3hDLE1BQU0sU0FBUyxHQUFRLE1BQU0sQ0FBQztJQUM5QixTQUFTLENBQUMsTUFBTSxDQUFDLFlBQVksR0FBRyxXQUFXLEVBQUUsQ0FBQztJQUM5QyxNQUFNLE9BQU8sR0FBRyxLQUFLLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsWUFBWSxFQUFFLFNBQVMsQ0FBQyxDQUFDO0lBQ3BFLDhDQUE4QztJQUU5QyxNQUFNLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxvQkFBb0IsRUFBRTtRQUM5QyxNQUFNLEVBQUUsS0FBSztRQUNiLFlBQVksRUFBRSxLQUFLO0tBQ3BCLENBQUMsQ0FBQztJQUNILE1BQU0sQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUM7SUFFdkIsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxZQUFZLENBQUMsQ0FBQztJQUN2RSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQztJQUMxQiw4QkFBOEI7SUFDOUIsT0FBTyxTQUFTLENBQUMsTUFBTSxDQUFDO0FBQzFCLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLDZCQUE2QixFQUFFLENBQUMsQ0FBQyxFQUFFO0lBQ3RDLFVBQVUsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUM7SUFDdkIsTUFBTSxTQUFTLEdBQVEsTUFBTSxDQUFDO0lBQzlCLFNBQVMsQ0FBQyxNQUFNLENBQUMsWUFBWSxHQUFHLFdBQVcsRUFBRSxDQUFDO0lBQzlDLE1BQU0sT0FBTyxHQUFHLEtBQUssQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxZQUFZLEVBQUUsU0FBUyxDQUFDLENBQUM7SUFDcEUsTUFBTSxNQUFNLEdBQUcsSUFBSSxNQUFNLENBQUMsb0JBQW9CLEVBQUU7UUFDOUMsTUFBTSxFQUFFLEtBQUs7UUFDYixZQUFZLEVBQUUsS0FBSztLQUNwQixDQUFDLENBQUM7SUFDSCxNQUFNLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLGFBQWEsR0FBRyxZQUFZLENBQUM7SUFDbEUsTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDO0lBQ3BCLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLFNBQVMsQ0FBQyxDQUFDO0lBQzFCLENBQUMsQ0FBQyxFQUFFLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxhQUFhLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDdEUsQ0FBQyxDQUFDLENBQUM7QUFFSCxTQUFTLFdBQVc7SUFDbEIsTUFBTSxPQUFPLEdBQVEsRUFBRSxDQUFDO0lBQ3hCLE9BQU87UUFDTCxPQUFPLENBQUMsR0FBVyxFQUFFLEtBQWE7WUFDaEMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLEtBQUssSUFBSSxFQUFFLENBQUM7UUFDN0IsQ0FBQztRQUNELE9BQU8sQ0FBQyxHQUFXO1lBQ2pCLE9BQU8sR0FBRyxJQUFJLE9BQU8sQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUM7UUFDOUMsQ0FBQztRQUNELFVBQVUsQ0FBQyxHQUFXO1lBQ3BCLE9BQU8sT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQ3RCLENBQUM7S0FDRixDQUFDO0FBQ0osQ0FBQyJ9