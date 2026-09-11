const form = document.getElementById("verification-form");
const contentInput = document.getElementById("content-input");
const characterCount = document.getElementById("character-count");
const inputLabel = document.getElementById("input-label");
const inputHint = document.getElementById("input-hint");

const fileInput = document.getElementById("file-input");
const browseButton = document.getElementById("browse-button");
const uploadArea = document.getElementById("upload-area");

const processingPanel = document.getElementById("processing-panel");
const resultsPanel = document.getElementById("results-panel");

const progressBar = document.getElementById("progress-bar");
const processingPercent = document.getElementById("processing-percent");
const processingTitle = document.getElementById("processing-title");

const confidenceScore = document.getElementById("confidence-score");
const confidenceMeterFill = document.getElementById("confidence-meter-fill");
const confidenceDescription = document.getElementById("confidence-description");

const evidenceOutput = document.getElementById("evidence-output");
const signalsList = document.getElementById("signals-list");

const newVerificationButton = document.getElementById("new-verification");

let selectedType = "website";
let selectedFile = null;

const typeConfig = {
website: {
label: "ENTER WEBSITE URL",
placeholder: "https://example.com",
hint: "Paste a URL to begin verification.",
accept: ""
},

 
article: {
    label: "ENTER ARTICLE URL OR TEXT",
    placeholder: "Paste an article URL or article text...",
    hint: "VeriCore will analyze the content and supporting sources.",
    accept: ""
},

tweet: {
    label: "ENTER SOCIAL POST URL OR TEXT",
    placeholder: "Paste a post URL or the post text...",
    hint: "Analyze claims, sources, and available contextual evidence.",
    accept: ""
},

image: {
    label: "ENTER IMAGE URL OR UPLOAD IMAGE",
    placeholder: "Paste an image URL or upload an image below...",
    hint: "Visual analysis can be combined with source and metadata signals.",
    accept: "image/*"
},

video: {
    label: "ENTER VIDEO URL OR UPLOAD VIDEO",
    placeholder: "Paste a video URL or upload a video below...",
    hint: "Video verification uses available metadata and analysis signals.",
    accept: "video/*"
},

pdf: {
    label: "ENTER PDF URL OR UPLOAD PDF",
    placeholder: "Paste a PDF URL or upload a PDF below...",
    hint: "Analyze document metadata, content, and available evidence.",
    accept: "application/pdf"
}
 

};

function updateInterface(type) {

 
selectedType = type;

const config = typeConfig[type];

inputLabel.textContent = config.label;
contentInput.placeholder = config.placeholder;
inputHint.textContent = config.hint;

selectedFile = null;
fileInput.value = "";

if (config.accept) {
    fileInput.accept = config.accept;
    uploadArea.style.display = "flex";
} else {
    fileInput.accept = "";
    uploadArea.style.display = "flex";
}

contentInput.value = "";
updateCharacterCount();
 

}

document.querySelectorAll(".type-button").forEach(button => {

 
button.addEventListener("click", () => {

    document
        .querySelectorAll(".type-button")
        .forEach(item => item.classList.remove("active"));

    button.classList.add("active");

    updateInterface(button.dataset.type);
});
 

});

contentInput.addEventListener("input", updateCharacterCount);

function updateCharacterCount() {

 
const count = contentInput.value.length;

characterCount.textContent =
    `${count.toLocaleString()} character${count === 1 ? "" : "s"}`;
 

}

browseButton.addEventListener("click", () => {
fileInput.click();
});

fileInput.addEventListener("change", event => {

 
const file = event.target.files[0];

if (!file) {
    return;
}

selectedFile = file;

inputHint.textContent =
    `Selected: ${file.name} (${formatFileSize(file.size)})`;

browseButton.textContent = "Change";
 

});

uploadArea.addEventListener("dragover", event => {

 
event.preventDefault();

uploadArea.style.borderColor = "rgba(216,255,62,0.7)";
 

});

uploadArea.addEventListener("dragleave", () => {

 
uploadArea.style.borderColor = "";
 

});

uploadArea.addEventListener("drop", event => {

 
event.preventDefault();

uploadArea.style.borderColor = "";

const file = event.dataTransfer.files[0];

if (!file) {
    return;
}

selectedFile = file;

inputHint.textContent =
    `Selected: ${file.name} (${formatFileSize(file.size)})`;

browseButton.textContent = "Change";
 

});

function formatFileSize(bytes) {

 
if (bytes < 1024) {
    return `${bytes} B`;
}

if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
}

if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
 

}

form.addEventListener("submit", async event => {

 
event.preventDefault();

const text = contentInput.value.trim();

if (!text && !selectedFile) {

    contentInput.focus();

    inputHint.textContent =
        "Enter content or upload a file to begin.";

    return;
}

await runVerification(text);
 

});

async function runVerification(text) {

 
form.closest(".verification-panel").classList.add("hidden");

resultsPanel.classList.add("hidden");
processingPanel.classList.remove("hidden");

window.scrollTo({
    top: processingPanel.offsetTop - 30,
    behavior: "smooth"
});

resetProcessing();

try {

    const progressPromise = animateProcessing();

    const request = buildRequest(text);

    const response = await fetch("/api/verify", request);

    const rawText = await response.text();

    let result;

    try {
        result = JSON.parse(rawText);
    } catch {
        result = {
            rawResponse: rawText
        };
    }

    await progressPromise;

    showResults(result, response.ok);

} catch (error) {

    await animateProcessing();

    showResults({
        error: error.message,
        message: "The verification request could not be completed."
    }, false);
}
 

}

function buildRequest(text) {

 
if (selectedFile) {

    const formData = new FormData();

    formData.append("type", selectedType);
    formData.append("content", text);
    formData.append("file", selectedFile);

    return {
        method: "POST",
        body: formData
    };
}

return {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },

    body: JSON.stringify({
        type: selectedType,
        content: text,
        input: text,
        url: selectedType === "website" ? text : undefined
    })
};
 

}

function resetProcessing() {

 
progressBar.style.width = "0%";
processingPercent.textContent = "0%";
processingTitle.textContent = "Analyzing evidence...";

document
    .querySelectorAll(".process-step")
    .forEach(step => {
        step.classList.remove("active", "complete");
    });

document
    .getElementById("step-retrieve")
    .classList.add("active");
 

}

async function animateProcessing() {

 
const steps = [
    {
        id: "step-retrieve",
        title: "Retrieving evidence...",
        percent: 25
    },

    {
        id: "step-source",
        title: "Analyzing sources...",
        percent: 50
    },

    {
        id: "step-evidence",
        title: "Building evidence graph...",
        percent: 75
    },

    {
        id: "step-score",
        title: "Calculating confidence...",
        percent: 95
    }
];

for (const step of steps) {

    processingTitle.textContent = step.title;

    document
        .querySelectorAll(".process-step")
        .forEach(item => {
            item.classList.remove("active");
        });

    const current = document.getElementById(step.id);

    current.classList.add("active");

    progressBar.style.width = `${step.percent}%`;
    processingPercent.textContent = `${step.percent}%`;

    await sleep(550);
}

progressBar.style.width = "100%";
processingPercent.textContent = "100%";

processingTitle.textContent = "Analysis complete.";

document
    .querySelectorAll(".process-step")
    .forEach(item => {
        item.classList.remove("active");
        item.classList.add("complete");
    });


}

function showResults(result, successfulRequest) {


processingPanel.classList.add("hidden");
resultsPanel.classList.remove("hidden");

window.scrollTo({
    top: resultsPanel.offsetTop - 30,
    behavior: "smooth"
});

const score = extractScore(result);

confidenceScore.textContent =
    score === null ? "--" : score;

confidenceMeterFill.style.width =
    score === null ? "0%" : `${score}%`;

confidenceDescription.textContent =
    describeConfidence(score);

const badge = document.getElementById("result-badge");

if (successfulRequest) {
    badge.textContent = "ANALYZED";
} else {
    badge.textContent = "REQUEST ERROR";
}

populateSignals(result, successfulRequest);

evidenceOutput.textContent =
    formatResult(result);

}

function extractScore(result) {


const possibleValues = [
    result?.confidence,
    result?.confidenceScore,
    result?.score,
    result?.verificationScore,
    result?.data?.confidence,
    result?.data?.confidenceScore,
    result?.data?.score,
    result?.result?.confidence,
    result?.result?.score
];

for (const value of possibleValues) {

    if (typeof value === "number") {

        if (value >= 0 && value <= 1) {
            return Math.round(value * 100);
        }

        if (value >= 0 && value <= 100) {
            return Math.round(value);
        }
    }

    if (typeof value === "string") {

        const parsed = parseFloat(value);

        if (!Number.isNaN(parsed)) {

            if (parsed >= 0 && parsed <= 1) {
                return Math.round(parsed * 100);
            }

            if (parsed >= 0 && parsed <= 100) {
                return Math.round(parsed);
            }
        }
    }
}

return null;
 

}

function describeConfidence(score) {

 
if (score === null) {
    return "The backend returned a result without a recognizable confidence score.";
}

if (score >= 90) {
    return "Very strong verification confidence based on the returned signals.";
}

if (score >= 75) {
    return "Strong verification confidence based on the returned signals.";
}

if (score >= 50) {
    return "Moderate confidence. Review the evidence before drawing a conclusion.";
}

return "Limited confidence. Additional evidence would strengthen the analysis.";
 

}

function populateSignals(result, successfulRequest) {

 
const signals = [];

if (successfulRequest) {

    signals.push({
        label: "Verification endpoint responded",
        active: true
    });

    if (
        result?.evidence ||
        result?.sources ||
        result?.data?.evidence ||
        result?.data?.sources
    ) {
        signals.push({
            label: "Evidence returned by engine",
            active: true
        });
    }

    if (
        result?.confidence !== undefined ||
        result?.score !== undefined ||
        result?.data?.confidence !== undefined ||
        result?.data?.score !== undefined
    ) {
        signals.push({
            label: "Confidence score detected",
            active: true
        });
    }

    signals.push({
        label: `${selectedType.toUpperCase()} analysis requested`,
        active: true
    });

} else {

    signals.push({
        label: "Verification request failed",
        active: false
    });

    signals.push({
        label: result?.error || "Check the backend response",
        active: false
    });
}

signalsList.innerHTML = "";

signals.forEach(signal => {

    const row = document.createElement("div");

    row.className = "signal";

    row.innerHTML = `
        <span class="signal-indicator"
              style="background:${signal.active ? "var(--accent)" : "var(--danger)"}">
        </span>
        <span>${escapeHtml(signal.label)}</span>
    `;

    signalsList.appendChild(row);
});
 

}

function formatResult(result) {

 
try {
    return JSON.stringify(result, null, 2);
} catch {
    return String(result);
}
 

}

function escapeHtml(value) {

 
return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
 

}

newVerificationButton.addEventListener("click", () => {

 
resultsPanel.classList.add("hidden");

form.closest(".verification-panel").classList.remove("hidden");

window.scrollTo({
    top: form.closest(".verification-panel").offsetTop - 30,
    behavior: "smooth"
});
 

});

function sleep(milliseconds) {

 
return new Promise(resolve => {
    setTimeout(resolve, milliseconds);
});
 

}

updateInterface("website");
updateCharacterCount();
