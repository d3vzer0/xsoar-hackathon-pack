
const chromium = require('chrome-aws-lambda');

exports.runScreenshot = async (req, res) => {
	try {
		const buffer = await takeScreenshot(req.body);

		res.setHeader("content-type", "text/plain");
		res.status(200).send(buffer);

	} catch(error) {
		res.setHeader("content-type", "application/json");
		res.status(422).send(JSON.stringify({
			error: error.message,
		}));
	}
};


async function takeScreenshot(params) {
	const browser = await chromium.puppeteer.launch({
        args: chromium.args,
        defaultViewport: chromium.defaultViewport,
        executablePath: await chromium.executablePath,
        headless: chromium.headless,
        ignoreHTTPSErrors: true,
    });

	const getWidth = parseInt(params.width) || 1024;
	const getHeight = parseInt(params.height) || 768;

	const page = await browser.newPage();
	await page.setViewport({ width: getWidth, height: getHeight });

	const proto = params.proto || "https"
	var fullUrl = `${proto}://${params.url}`;
	await page.goto(fullUrl, {waitUntil: 'networkidle2'});

	const buffer = await page.screenshot({ encoding: "base64" });

	await page.close();
	await browser.close();
  return buffer;
}
