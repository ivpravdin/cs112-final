#include "injection_script.h"

const char *injection_script = "<script>(function () {"
    "const container = document.createElement('div');"
    "container.style.position = 'fixed';"
    "container.style.bottom = '20px';"
    "container.style.left = '20px';"
    "container.style.width = '320px';"
    "container.style.padding = '10px 20px';"
    "container.style.backgroundColor = '#f9f9f9';"
    "container.style.boxShadow = '0px 8px 20px rgba(0, 0, 0, 0.2)';"
    "container.style.borderRadius = '10px';"
    "container.style.zIndex = '1000';"
    "container.style.fontFamily = 'Arial, sans-serif';"
    "container.style.lineHeight = '1.5';"
    "container.style.transition = 'all 0.3s ease';"
    "container.style.display = 'none';"

    "const titleWrapper = document.createElement('div');"
    "titleWrapper.style.display = 'flex';"
    "titleWrapper.style.justifyContent = 'space-between';"
    "titleWrapper.style.alignItems = 'center';"
    "titleWrapper.style.marginBottom = '15px';"

    "const label = document.createElement('p');"
    "label.innerText = 'Ask about this product:';"
    "label.style.fontSize = '16px';"
    "label.style.color = '#333';"
    "label.style.margin = '0';"

    "const toggleButton = document.createElement('button');"
    "toggleButton.innerText = '▼';"
    "toggleButton.style.width = '30px';"
    "toggleButton.style.height = '30px';"
    "toggleButton.style.backgroundColor = '#d50000';"
    "toggleButton.style.color = '#fff';"
    "toggleButton.style.border = 'none';"
    "toggleButton.style.borderRadius = '5px';"
    "toggleButton.style.cursor = 'pointer';"
    "toggleButton.style.fontSize = '12px';"
    "toggleButton.style.fontWeight = 'bold';"
    "toggleButton.style.transition = 'transform 0.3s ease';"

    "titleWrapper.appendChild(label);"
    "titleWrapper.appendChild(toggleButton);"

    "const input = document.createElement('textarea');"
    "input.placeholder = 'Type your question here...';"
    "input.style.width = '100%';"
    "input.style.height = '80px';"
    "input.style.padding = '10px';"
    "input.style.border = '1px solid #ccc';"
    "input.style.borderRadius = '6px';"
    "input.style.marginBottom = '10px';"
    "input.style.resize = 'none';"
    "input.style.fontSize = '14px';"

    "const button = document.createElement('button');"
    "button.innerText = 'Ask';"
    "button.style.width = '100%';"
    "button.style.padding = '10px';"
    "button.style.backgroundColor = '#d50000';"
    "button.style.color = '#fff';"
    "button.style.border = 'none';"
    "button.style.borderRadius = '6px';"
    "button.style.cursor = 'pointer';"
    "button.style.fontSize = '16px';"
    "button.style.fontWeight = 'bold';"
    "button.onmouseover = () => {"
        "button.style.backgroundColor = '#b30000';"
    "};"
    "button.onmouseout = () => {"
        "button.style.backgroundColor = '#d50000';"
    "};"

    "const response = document.createElement('div');"
    "response.style.marginTop = '10px';"
    "response.style.padding = '10px';"
    "response.style.backgroundColor = '#f0f0f0';"
    "response.style.border = '1px solid #ccc';"
    "response.style.borderRadius = '6px';"
    "response.style.fontSize = '14px';"
    "response.style.color = '#333';"
    "response.style.display = 'none';"

    "container.appendChild(titleWrapper);"
    "container.appendChild(input);"
    "container.appendChild(button);"
    "container.appendChild(response);"
    "document.body.appendChild(container);"

    "let isMinimized = true;"
    "container.style.height = '50px';"
    "container.style.padding = '10px 20px';"
    "label.style.display = 'block';"
    "label.style.marginBottom = '0px';"
    "input.style.display = 'none';"
    "button.style.display = 'none';"
    "response.style.display = 'none';"
    "toggleButton.innerText = '▲';"

    "toggleButton.addEventListener('click', () => {"
        "if (isMinimized) {"
            "container.style.height = 'auto';"
            "container.style.padding = '20px';"
            "label.style.display = 'block';"
            "input.style.display = 'block';"
            "button.style.display = 'block';"
            "if (response.innerText.trim() !== '') {"
                "response.style.display = 'block';"
            "}"
            "toggleButton.innerText = '▼';"
        "} else {"
            "container.style.height = '50px';"
            "container.style.padding = '10px 20px';"
            "label.style.display = 'block';"
            "input.style.display = 'none';"
            "button.style.display = 'none';"
            "response.style.display = 'none';"
            "toggleButton.innerText = '▲';"
        "}"
        "isMinimized = !isMinimized;"
    "});"

    "function minimizeContainer(Minimize) {"
        "if (Minimize) {"
            "container.style.height = '50px';"
            "container.style.padding = '10px 20px';"
            "label.style.display = 'block';"
            "input.style.display = 'none';"
            "button.style.display = 'none';"
            "response.style.display = 'none';"
            "toggleButton.innerText = '▲';"
            "isMinimized = true;"
        "} else {"
            "container.style.height = 'auto';"
            "container.style.padding = '20px';"
            "label.style.display = 'block';"
            "input.style.display = 'block';"
            "button.style.display = 'block';"
            "if (response.innerText.trim() !== '') {"
                "response.style.display = 'block';"
            "}"
            "toggleButton.innerText = '▼';"
            "isMinimized = false;"
        "}"
    "}"

    "let url = window.location.href;"

    "function checkAndToggleContainerVisibility() {"
        "const isTargetProductPage = /^https:\\/\\/www\\.target\\.com\\/p\\//.test(location.href);"
        "container.style.display = isTargetProductPage ? 'block' : 'none';"
        "if (!isTargetProductPage) {"
            "minimizeContainer(true);"
            "input.value = '';"
            "response.innerText = '';"
            "response.style.display = 'none';"
            "url = window.location.href;"
        "}"
        "const currentTcinMatch = window.location.href.match(/\\/A-(\\d+)/);"
        "const previousTcinMatch = url.match(/\\/A-(\\d+)/);"
        "if (url !== window.location.href && currentTcinMatch && previousTcinMatch && currentTcinMatch[1] !== previousTcinMatch[1]) {"
            "input.value = '';"
            "response.innerText = '';"
            "response.style.display = 'none';"
            "url = window.location.href;"
        "}"
    "}"

    "checkAndToggleContainerVisibility();"

    "const originalPushState = history.pushState;"
    "const originalReplaceState = history.replaceState;"

    "history.pushState = function (...args) {"
        "originalPushState.apply(this, args);"
        "checkAndToggleContainerVisibility();"
    "};"

    "history.replaceState = function (...args) {"
        "originalReplaceState.apply(this, args);"
        "checkAndToggleContainerVisibility();"
    "};"

    "window.addEventListener('popstate', checkAndToggleContainerVisibility);"

    "function findUniqueNestedKeys(obj, keys) {"
        "const results = new Set();"
        "function searchRecursive(currentObj) {"
            "if (!currentObj || typeof currentObj !== 'object') return;"
            "for (const key in currentObj) {"
                "if (keys.includes(key)) {"
                    "results.add(currentObj[key]);"
                "}"
                "searchRecursive(currentObj[key]);"
            "}"
        "}"
        "searchRecursive(obj);"
        "if (results.size === 0) results.add(null);"
        "return Array.from(results);"
    "}"

    "async function getProductDescription() {"
        "try {"
            "const apiKey = window.__CONFIG__?.services?.redsky?.apiKey;"
            "if (!apiKey) {"
                "throw new Error('RedSky API key not found.');"
            "}"

            "function getStoreIdFromCookie() {"
                "const cookies = document.cookie;"
                "const fiatsCookie = cookies.split('; ').find(cookie => cookie.startsWith('fiatsCookie='));"
                "if (fiatsCookie) {"
                    "const match = fiatsCookie.match(/DSI_(\\d+)/);"
                    "if (match) {"
                        "return match[1];"
                    "}"
                "}"
                "console.error('Store ID not found in fiatsCookie.');"
                "return null;"
            "}"

            "const pricingStoreId = getStoreIdFromCookie();"

            "const targetUrl = window.location.href;"
            "const urlParams = new URLSearchParams(new URL(targetUrl).search);"
            "const tcin = urlParams.has('preselect') ? urlParams.get('preselect') : targetUrl.match(/\\/A-(\\d+)/)[1];"

            "const redskyUrl = `https://redsky.target.com/redsky_aggregations/v1/web/pdp_client_v1?key=${apiKey}&tcin=${tcin}&is_bot=true&pricing_store_id=${pricingStoreId}`;"
            "const response = await fetch(redskyUrl);"
            "if (!response.ok) {"
                "throw new Error(`Failed to fetch product data: ${response.statusText}`);"
            "}"

            "const productData = await response.json();"

            "let product = null;"

            "if (productData?.data?.product?.children) {"
                "product = productData.data.product.children.find(child => child.tcin === tcin);"
            "} else {"
                "product = productData.data.product;"
            "}"

            "return {"
                "title: product?.item?.product_description?.title,"
                "tcin: product?.tcin,"
                "description: product?.item?.product_description?.downstream_description,"
                "specifications: product?.item?.product_description?.bullet_descriptions,"
                "highlights: product?.item?.product_description?.soft_bullets,"
                "price: product?.price,"
                "most_recent_ratings: productData?.data?.product?.ratings_and_reviews?.most_recent,"
                "reviews_statistics: productData?.data?.product?.ratings_and_reviews?.statistics,"
                "drug_facts: product?.item?.enrichment?.drug_facts,"
                "nutrition_facts: product?.item?.enrichment?.nutrition_facts,"
            "}"
        "} catch (error) {"
            "console.error('An error occurred:', error);"
            "return null;"
        "}"
    "}"

    "const apiEndpoint = 'https://llmproxy.com/';"

    "async function askChatGPT(question) {"

        "const product = await getProductDescription();"
        
        "const headers = {"
            "'Content-Type': 'application/json',"
        "};"

        "const body = JSON.stringify({"
            "'model': '4o-mini',"
            "'system': 'You are an AI assistant at Target. You are given a product description. You need to answer customer questions about the product. Answer questions in clear and concise language. If you don\\'t know the answer, you should say so. Limit your responses to 3-4 sentences. Product Description: ' + JSON.stringify(product),"
            "'query': question,"
            "'temperature': 0.5,"
            "'lastk': 10,"
            "'session_id': product?.tcin,"
        "});"

        "console.log('Request data:', body);"

        "try {"
            "console.log('Sending request to OpenAI...');"
            "const res = await fetch(apiEndpoint, { method: 'POST', headers, body });"
            "console.log('Response status:', res.status);"

            "if (!res.ok) {"
                "console.error('Error response:', await res.text());"
                "throw new Error(`Error: ${res.status}`);"
            "}"

            "const data = await res.json();"
            "console.log('Response data:', data);"
            "return data.result;"
        "} catch (err) {"
            "console.error('Detailed error:', err);"
            "console.error('Error stack:', err.stack);"
            "return 'Error: Unable to fetch response from ChatGPT.';"
        "}"
    "}"

    "function typeResponseWordByWord(text) {"
        "const words = text.split(' ');"
        "response.innerText = '';"
        "let wordIndex = 0;"
        "function typeNextWord() {"
            "if (wordIndex < words.length) {"
                "response.innerText += (wordIndex === 0 ? '' : ' ') + words[wordIndex];"
                "wordIndex++;"
                "setTimeout(typeNextWord, 150);"
            "}"
        "}"
        "typeNextWord();"
    "}"

    "button.addEventListener('click', async () => {"
        "const query = input.value;"
        "if (!query) {"
            "response.style.display = 'block';"
            "response.innerText = 'Please enter a question.';"
            "return;"
        "}"
        "response.style.display = 'block';"
        "response.innerText = 'Thinking...';"
        "const answer = await askChatGPT(query);"
        "typeResponseWordByWord(answer);"
    "});"
    "}) ();</script>";