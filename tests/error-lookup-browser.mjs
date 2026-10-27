import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
const browser=await chromium.launch({channel:'msedge',headless:true});
try {
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 await page.goto('http://localhost:3600');
 await page.locator('#error-lookup-open').click();
 await page.locator('#error-lookup-code').fill('AADSTS53000');
 await page.locator('#error-lookup-form button').click();
 assert.equal(await page.locator('#error-lookup-link').getAttribute('href'),'https://login.microsoftonline.com/error?code=53000');
 await page.frameLocator('#error-lookup-frame').locator('table').waitFor({timeout:30000});
 assert.match(await page.frameLocator('#error-lookup-frame').locator('table').innerText(),/53000/);
 await page.screenshot({path:'.runtime/error-lookup-desktop.png'});
 await page.locator('#error-lookup-code').fill('https://example.com');
 await page.locator('#error-lookup-form button').click();
 assert.equal(await page.locator('#error-lookup-code').evaluate(e=>e.validity.valid),false);
 assert.equal(await page.locator('#error-lookup-frame').getAttribute('src'),'https://login.microsoftonline.com/error?code=53000');
 await page.keyboard.press('Escape');
 assert.equal(await page.locator('#error-lookup-dialog').isVisible(),false);
 await page.locator('[data-view="signins"]').click();
 await page.locator('#signin-run').click();
 await page.locator('[data-error-code]').first().click();
 assert.equal(await page.locator('#error-lookup-code').inputValue(),'53000');
 await page.setViewportSize({width:390,height:844});
 assert.equal(await page.locator('#error-lookup-dialog').evaluate(e=>e.getBoundingClientRect().width<=390),true);
 await page.screenshot({path:'.runtime/error-lookup-mobile.png'});
 console.log('PASS: live Microsoft embedded explanation, prefix normalization, invalid input, event shortcut, Escape and mobile drawer.');
}finally{await browser.close();}
