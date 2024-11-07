// escape special regex characters
function escapeSpecialChar(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// normalize whitespace
function normalizeWhitespace(string) {
    return string.replace(/\s+/g, ' ').trim();
}

// decode HTML entities
function decodeHTMLEntities(text) {
    var txt = document.createElement("textarea");
    txt.innerHTML = text;
    return txt.value;
}

function highlightClause(sentence1, sentence2, buttonId, clauseNumber) {
    const narrative1 = document.getElementById('narrative1');
    const narrative2 = document.getElementById('narrative2');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;
    const highlightedSentence1 = `${startToken}<span class="highlight-overlap">${sentence1}</span>${endToken}`;
    const highlightedSentence2 = `${startToken}<span class="highlight-overlap">${sentence2}</span>${endToken}`;

    // Escape special characters
    const escapedSentence1 = escapeSpecialChar(sentence1); 
    const escapedSentence2 = escapeSpecialChar(sentence2);
    const escapedHighlightedSentence1 = escapeSpecialChar(highlightedSentence1);
    const escapedHighlightedSentence2 = escapeSpecialChar(highlightedSentence2);

    // Decode and normalize narratives
    const decodedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
    const decodedNarrative2 = decodeHTMLEntities(narrative2.innerHTML);
    const normalizedNarrative1 = normalizeWhitespace(decodedNarrative1);
    const normalizedNarrative2 = normalizeWhitespace(decodedNarrative2);

    // Normalize sentences
    const normalizedSentence1 = normalizeWhitespace(sentence1);
    const normalizedSentence2 = normalizeWhitespace(sentence2);
    const normalizedHighlightedSentence1 = normalizeWhitespace(highlightedSentence1);
    const normalizedHighlightedSentence2 = normalizeWhitespace(highlightedSentence2);

    // Check if the sentences are currently highlighted
    const isHighlighted1 = normalizedNarrative1.includes(normalizedHighlightedSentence1);
    const isHighlighted2 = normalizedNarrative2.includes(normalizedHighlightedSentence2);

    // Check if sentences exist in narratives
    const sentenceExistsNarrative1 = normalizedNarrative1.includes(normalizedSentence1);
    const sentenceExistsNarrative2 = normalizedNarrative2.includes(normalizedSentence2);

    // Check if either sentence exists: show error message
    if (!sentenceExistsNarrative1 && !sentenceExistsNarrative2) {
        alert("Exact match not found in both documents; you must check the documents.");
        return;
    }

    if (isHighlighted1 || isHighlighted2) {
        // Remove the highlighted and tokens by replacing them with original
        if (isHighlighted1) {
            narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(escapedHighlightedSentence1, 'g'), sentence1);
        }
        if (isHighlighted2) {
            narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(escapedHighlightedSentence2, 'g'), sentence2);
        }


        // Check if highlights are still present and update narratives
        const updatedDecodedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
        const updatedDecodedNarrative2 = decodeHTMLEntities(narrative2.innerHTML);
        const updatedNormalizedNarrative1 = normalizeWhitespace(updatedDecodedNarrative1);
        const updatedNormalizedNarrative2 = normalizeWhitespace(updatedDecodedNarrative2);

        const stillHighlighted1 = updatedNormalizedNarrative1.includes(normalizedHighlightedSentence1);
        const stillHighlighted2 = updatedNormalizedNarrative2.includes(normalizedHighlightedSentence2);

        if (!stillHighlighted1 && !stillHighlighted2) {
            button.classList.remove('active');
            button.innerText = 'Highlight';
        }
        
    } 
    else {
        // Add highlight with start end tokens
        let highlighted = false;
        if (sentenceExistsNarrative1) {
            narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(escapedSentence1, 'g'), highlightedSentence1);
            highlighted = true;

        }
        else {
            alert("Exact match not found in Document 1; you must check the document.");
        }

        if (sentenceExistsNarrative2) {
            narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(escapedSentence2, 'g'), highlightedSentence2);
            highlighted = true;
        }
        else {
            alert("Exact match not found in Document 2; you must check the document.");

        }

        if (highlighted) {
            button.classList.add('active');
            button.innerText = 'Hide';

            window.scrollTo({top: 0, behavior: 'smooth'});
        }
    }
}

function highlightUnique1(sentence1, buttonId, clauseNumber) {
    const narrative1 = document.getElementById('narrative1');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;
    const highlightedSentence1 = `${startToken}<span class="highlight-overlap">${sentence1}</span>${endToken}`;

    // Escape special characters 
    const escapedSentence1 = escapeSpecialChar(sentence1);
    const escapedHighlightedSentence1 = escapeSpecialChar(highlightedSentence1);

    // Decode and normalize narrative
    const decodedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
    const normalizedNarrative1 = normalizeWhitespace(decodedNarrative1);

    // Normalize sentences
    const normalizedSentence1 = normalizeWhitespace(sentence1);
    const normalizedHighlightedSentence1 = normalizeWhitespace(highlightedSentence1);

    // Check if the sentence is currently highlighted
    const isHighlighted1 = normalizedNarrative1.includes(normalizedHighlightedSentence1);

    const sentenceExistsNarrative1 = normalizedNarrative1.includes(normalizedSentence1);

    if (!sentenceExistsNarrative1) {
        alert("Exact match not found in Document 1; you must check the document.");

        return;
    }


    if (isHighlighted1) {
        // Remove highlight
        narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(escapedHighlightedSentence1, 'g'), sentence1);

        // Update narrative + check if the highlight is still present
        const updatedDecodedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
        const updatedNormalizedNarrative1 = normalizeWhitespace(updatedDecodedNarrative1);
        const stillHighlighted1 = updatedNormalizedNarrative1.includes(normalizedHighlightedSentence1);

        if (!stillHighlighted1) {
            button.classList.remove('active');
            button.innerText = 'Highlight';
        }
    } 
    else {
        // Add highlights with Start and End tokens
        narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(escapedSentence1, 'g'), highlightedSentence1);
        button.classList.add('active');     // Activate button
        button.innerText = 'Hide';          // Change button text
        // Scroll to the top smoothly
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
}

function highlightUnique2(sentence2, buttonId, clauseNumber) {
    const narrative2 = document.getElementById('narrative2');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;
    const highlightedSentence2 = `${startToken}<span class="highlight-overlap">${sentence2}</span>${endToken}`;

    // Escape special characters
    const escapedSentence2 = escapeSpecialChar(sentence2);
    const escapedHighlightedSentence2 = escapeSpecialChar(highlightedSentence2);
    
    // Decode and normalize narrative
    const decodedNarrative2 = decodeHTMLEntities(narrative2.innerHTML);
    const normalizedNarrative2 = normalizeWhitespace(decodedNarrative2);

    // Normalize sentences
    const normalizedSentence2 = normalizeWhitespace(sentence2);
    const normalizedHighlightedSentence2 = normalizeWhitespace(highlightedSentence2);

    // Check if the sentence is currently highlighted
    const isHighlighted2 = normalizedNarrative2.includes(normalizedHighlightedSentence2);

    // Check if the sentence exists in narrative:
    const sentenceExistsNarrative2 = normalizedNarrative2.includes(normalizedSentence2);

    if (!sentenceExistsNarrative2) {
        alert("Exact match not found in Document 2; you must check the document.");

        return;
    }

    if (isHighlighted2) {
        // Remove highlights and tokens by replacing the highlighted structure with the original sentence
        narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(escapedHighlightedSentence2, 'g'), sentence2);
        button.classList.remove('active');  // Deactivate button
        button.innerText = 'Highlight';     // Reset button text
    } 
    else {
        // Add highlights with Start and End tokens
        narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(escapedSentence2, 'g'), highlightedSentence2);
        button.classList.add('active');     // Activate button
        button.innerText = 'Hide';          // Change button text
        // Scroll to the top smoothly
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
}

// Event Listener for Scrolling Based on URL Parameters
document.addEventListener("DOMContentLoaded", function() {
    const urlParams = new URLSearchParams(window.location.search);
    const action = urlParams.get("action");

    if (action === "showOverlap") { 
        const overlapSection = document.getElementById("overlapSection");
        if (overlapSection) {
            overlapSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
    else if (action === "showConflict") { // Updated to "showConflict" for conflict section
        const conflictSection = document.getElementById("conflictSection");
        if (conflictSection) {
            conflictSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    } 
    else if (action === "showUnique1") { // Corrected comment to match the action
        const unique1Section = document.getElementById("unique1Section");
        if (unique1Section) {
            unique1Section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
    else if (action === "showUnique2") { // Corrected comment to match the action
        const unique2Section = document.getElementById("unique2Section");
        if (unique2Section) {
            unique2Section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    else if (action === "hide") {
        const narrativeBox = document.getElementById("narrativeBox");
        if (narrativeBox) {
            narrativeBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }
});
