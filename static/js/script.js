function highlightClause(sentence1, sentence2, buttonId, clauseNumber) {
    const narrative1 = document.getElementById('narrative1');
    const narrative2 = document.getElementById('narrative2');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;
    const highlightedSentence1 = `${startToken}<span class="highlight-overlap">${sentence1}</span>${endToken}`;
    const highlightedSentence2 = `${startToken}<span class="highlight-overlap">${sentence2}</span>${endToken}`;

    // Check if the sentences are currently highlighted
    const isHighlighted1 = narrative1.innerHTML.includes(highlightedSentence1);
    const isHighlighted2 = narrative2.innerHTML.includes(highlightedSentence2);

    if (isHighlighted1 && isHighlighted2) {
        // Remove highlights and tokens by replacing the highlighted structure with the original sentence
        narrative1.innerHTML = narrative1.innerHTML.replace(highlightedSentence1, sentence1);
        narrative2.innerHTML = narrative2.innerHTML.replace(highlightedSentence2, sentence2);
        button.classList.remove('active');  // Deactivate button
        button.innerText = 'Highlight';     // Reset button text
    } 
    else {
        // Add highlights with Start and End tokens
        narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(sentence1, 'g'), highlightedSentence1);
        narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(sentence2, 'g'), highlightedSentence2);
        button.classList.add('active');     // Activate button
        button.innerText = 'Hide';   // Change button text
        // Scroll to the top smoothly
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
      }




function highlightUnique1(sentence1, buttonId, clauseNumber) {
    const narrative1 = document.getElementById('narrative1');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;
    const highlightedSentence1 = `${startToken}<span class="highlight-overlap">${sentence1}</span>${endToken}`;

    // Check if the sentences are currently highlighted
    const isHighlighted1 = narrative1.innerHTML.includes(highlightedSentence1);

    if (isHighlighted1) {
        // Remove highlights and tokens by replacing the highlighted structure with the original sentence
        narrative1.innerHTML = narrative1.innerHTML.replace(highlightedSentence1, sentence1);
        button.classList.remove('active');  // Deactivate button
        button.innerText = 'Highlight';     // Reset button text
    } 
    else {
        // Add highlights with Start and End tokens
        narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(sentence1, 'g'), highlightedSentence1);
        button.classList.add('active');     // Activate button
        button.innerText = 'Hide';   // Change button text
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
    
        // Check if the sentences are currently highlighted
        const isHighlighted2 = narrative2.innerHTML.includes(highlightedSentence2);
    
        if (isHighlighted2) {
            // Remove highlights and tokens by replacing the highlighted structure with the original sentence
            narrative2.innerHTML = narrative2.innerHTML.replace(highlightedSentence2, sentence2);
            button.classList.remove('active');  // Deactivate button
            button.innerText = 'Highlight';     // Reset button text
        } 
        else {
            // Add highlights with Start and End tokens
            narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(sentence2, 'g'), highlightedSentence2);
            button.classList.add('active');     // Activate button
            button.innerText = 'Hide';   // Change button text
            // Scroll to the top smoothly
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
          }
    



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
    else if (action === "showUnique1") { // Updated to "showConflict" for conflict section
        const conflictSection = document.getElementById("unique1Section");
        if (conflictSection) {
            conflictSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }else if (action === "showUnique2") { // Updated to "showConflict" for conflict section
        const conflictSection = document.getElementById("unique2Section");
        if (conflictSection) {
            conflictSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
    
    else if (action === "hide") {
        const narrativeBox = document.getElementById("narrativeBox");
        if (narrativeBox) {
            narrativeBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }
});
