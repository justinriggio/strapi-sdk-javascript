import { AxiosInstance, AxiosRequestConfig } from 'axios';
export interface Authentication {
    user: object;
    jwt: string;
}
export declare type Provider = 'facebook' | 'google' | 'github' | 'twitter';
export interface ProviderToken {
    access_token?: string;
    code?: string;
    oauth_token?: string;
}
export interface CookieConfig {
    key: string;
    options: object;
}
export interface LocalStorageConfig {
    key: string;
}
export interface StoreConfig {
    cookie?: CookieConfig | false;
    localStorage?: LocalStorageConfig | false;
}
export default class Strapi {
    axios: AxiosInstance;
    storeConfig: StoreConfig;
    /**
     * Default constructor.
     * @param baseURL Your Strapi host.
     * @param axiosConfig Extend Axios configuration.
     */
    constructor(baseURL: string, storeConfig?: StoreConfig, requestConfig?: AxiosRequestConfig);
    /**
     * Axios request
     * @param method Request method
     * @param url Server URL
     * @param requestConfig Custom Axios config
     */
    request(method: string, url: string, requestConfig?: AxiosRequestConfig): Promise<any>;
    /**
     * Register a new user.
     * @param username
     * @param email
     * @param password
     * @returns Authentication User token and profile
     */
    register(username: string, email: string, password: string, firstname: string, lastname: string, company: string, optin: string): Promise<Authentication>;
    /**
     * Login by getting an authentication token.
     * @param identifier Can either be an email or a username.
     * @param password
     * @returns Authentication User token and profile
     */
    login(identifier: string, password: string): Promise<Authentication>;
    /**
     * Sends an email to a user with the link of your reset password page.
     * This link contains an URL param code which is required to reset user password.
     * Received link url format https://my-domain.com/rest-password?code=privateCode.
     * @param email
     * @param url Link that user will receive.
     */
    forgotPassword(email: string, url: string): Promise<void>;
    /**
     * Reset the user password.
     * @param code Is the url params received from the email link (see forgot password).
     * @param password
     * @param passwordConfirmation
     */
    resetPassword(code: string, password: string, passwordConfirmation: string): Promise<void>;
    /**
     * Retrieve the connect provider URL
     * @param provider
     */
    getProviderAuthenticationUrl(provider: Provider): string;
    /**
     * Authenticate the user with the token present on the URL (for browser) or in `params` (on Node.js)
     * @param provider
     * @param params
     */
    authenticateProvider(provider: Provider, params?: ProviderToken): Promise<Authentication>;
    /**
     * List entries
     * @param contentTypePluralized
     * @param params Filter and order queries.
     */
    getEntries(contentTypePluralized: string, params?: AxiosRequestConfig['params']): Promise<object[]>;
    /**
     * Get the total count of entries with the provided criteria
     * @param contentType
     * @param params Filter and order queries.
     */
    getEntryCount(contentType: string, params?: AxiosRequestConfig['params']): Promise<object[]>;
    /**
     * Get a specific entry
     * @param contentTypePluralized Type of entry pluralized
     * @param id ID of entry
     */
    getEntry(contentTypePluralized: string, id: string): Promise<object>;
    /**
     * Create data
     * @param contentTypePluralized Type of entry pluralized
     * @param data New entry
     */
    createEntry(contentTypePluralized: string, data: AxiosRequestConfig['data']): Promise<object>;
    /**
     * Update data
     * @param contentTypePluralized Type of entry pluralized
     * @param id ID of entry
     * @param data
     */
    updateEntry(contentTypePluralized: string, id: string, data: AxiosRequestConfig['data']): Promise<object>;
    /**
     * Delete an entry
     * @param contentTypePluralized Type of entry pluralized
     * @param id ID of entry
     */
    deleteEntry(contentTypePluralized: string, id: string): Promise<object>;
    /**
     * Search for files
     * @param query Keywords
     */
    searchFiles(query: string): Promise<object[]>;
    /**
     * Get files
     * @param params Filter and order queries
     * @returns Object[] Files data
     */
    getFiles(params?: AxiosRequestConfig['params']): Promise<object[]>;
    /**
     * Get file
     * @param id ID of entry
     */
    getFile(id: string): Promise<object>;
    /**
     * Upload files
     *
     * ### Browser example
     * ```js
     * const form = new FormData();
     * form.append('files', fileInputElement.files[0], 'file-name.ext');
     * form.append('files', fileInputElement.files[1], 'file-2-name.ext');
     * const files = await strapi.upload(form);
     * ```
     *
     * ### Node.js example
     * ```js
     * const FormData = require('form-data');
     * const fs = require('fs');
     * const form = new FormData();
     * form.append('files', fs.createReadStream('./file-name.ext'), 'file-name.ext');
     * const files = await strapi.upload(form, {
     *   headers: form.getHeaders()
     * });
     * ```
     *
     * @param data FormData
     * @param requestConfig
     */
    upload(data: FormData, requestConfig?: AxiosRequestConfig): Promise<object>;
    /**
     * Set token on Axios configuration
     * @param token Retrieved by register or login
     */
    setToken(token: string, comesFromStorage?: boolean): void;
    /**
     * Remove token from Axios configuration
     */
    clearToken(): void;
    /**
     * Check if it runs on browser
     */
    private isBrowser;
}
