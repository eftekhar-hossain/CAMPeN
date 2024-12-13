document.addEventListener('DOMContentLoaded', function() {
    // Retrieve answered clauses from localStorage or initialize an empty array
    let answeredClauses = JSON.parse(localStorage.getItem('answeredClauses')) || [];

    // Function to move a clause to the bottom of its parent container
    function moveClauseToBottom(clauseItem) {
        const clauseBox = clauseItem.parentNode;
        clauseBox.removeChild(clauseItem);
        clauseBox.appendChild(clauseItem);
    }

    // Function to handle response button click
    function handleResponseButtonClick(event) {
        const button = event.currentTarget;
        const clauseId = button.getAttribute('data-clause-id');
        const clauseType = button.getAttribute('data-clause-type');
        const choice = button.getAttribute('data-choice');
        const sentence1 = button.getAttribute('data-sentence-1'); 
        const sentence2 = button.getAttribute('data-sentence-2'); 

        // Prepare data to send to the server
        const data = {
            'clause_id': clauseId,
            'clause_type': clauseType,
            'choice': choice,
            'sentence_1': sentence1,
            'sentence_2': sentence2
        };

        // Retrieve the CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

        // Send the data to the server using fetch
        fetch('/record_response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(result => {
            if (result.status === 'success') {
                const clauseItem = button.closest('.clause-item');
                const parentDiv = button.parentElement;
                const buttons = parentDiv.querySelectorAll('.response-button');

                // Disable all response buttons and remove active class
                buttons.forEach(btn => {
                    btn.disabled = true;
                    btn.classList.remove('selected-response');
                });

                // Add 'selected-response' class to the clicked button for visual feedback
                button.classList.add('selected-response');

                // Remove existing redo button if any
                let existingRedo = parentDiv.querySelector('.redo-button');
                if (existingRedo) {
                    existingRedo.remove();
                }

                // Create and insert the "Redo" button
                const redoButton = document.createElement('button');
                redoButton.textContent = 'Redo';
                redoButton.className = 'btn btn-warning btn-sm me-2 redo-button';
                parentDiv.insertBefore(redoButton, parentDiv.firstChild);

                // Add event listener to the "Redo" button
                redoButton.addEventListener('click', function() {
                    // Re-enable all response buttons
                    buttons.forEach(btn => btn.disabled = false);
                    buttons.forEach(btn => btn.classList.remove('selected-response'));
                    redoButton.remove();

                    // Prepare data to send to the server to delete response
                    const deleteData = {
                        'clause_id': clauseId,
                        'clause_type': clauseType
                    };

                    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

                    // Delete response from the server
                    fetch('/delete_response', {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken
                        },
                        body: JSON.stringify(deleteData)
                    })
                    .then(response => response.json())
                    .then(result => {
                        if (result.status === 'success') {
                            console.log('Response deleted from database');
                            // Remove from answeredClauses
                            answeredClauses = answeredClauses.filter(id => id !== clauseId);
                            localStorage.setItem('answeredClauses', JSON.stringify(answeredClauses));
                            // Optionally move clause back up: 
                            // To do so, you'd need to remember original positions or just leave it as is.
                        } else {
                            console.error('Error deleting response:', result.message);
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                    });
                });

                // Move the clause item to the bottom
                moveClauseToBottom(clauseItem);

                // Add this clause to answeredClauses in localStorage
                if (!answeredClauses.includes(clauseId)) {
                    answeredClauses.push(clauseId);
                    localStorage.setItem('answeredClauses', JSON.stringify(answeredClauses));
                }

            } else {
                console.error('Error recording response:', result.message);
            }
        })        
        .catch(error => {
            console.error('Error:', error);
        });
    }

    // Attach event listeners to all response buttons
    document.querySelectorAll('.response-button').forEach(button => {
        button.addEventListener('click', handleResponseButtonClick);
    });

    // Pre-select saved responses and add redo buttons
    if (typeof savedResponses !== 'undefined' && savedResponses !== null) {
        for (const clauseId in savedResponses) {
            if (savedResponses.hasOwnProperty(clauseId)) {
                const choice = savedResponses[clauseId];
                const clauseType = clauseId.split('_')[0]; // Derive clauseType from clauseId
                const button = document.querySelector(`.response-button[data-clause-id="${clauseId}"][data-clause-type="${clauseType}"][data-choice="${choice}"]`);

                if (button) {
                    const parentDiv = button.parentElement;
                    const buttons = parentDiv.querySelectorAll('.response-button');

                    // Disable all buttons and highlight the selected one
                    buttons.forEach(btn => {
                        btn.disabled = true;
                        btn.classList.remove('selected-response');
                    });
                    button.classList.add('selected-response');

                    // Create and insert the "Redo" button
                    const redoButton = document.createElement('button');
                    redoButton.textContent = 'Redo';
                    redoButton.className = 'btn btn-warning btn-sm me-2 redo-button';
                    parentDiv.insertBefore(redoButton, parentDiv.firstChild);

                    // Add event listener to "Redo" button
                    redoButton.addEventListener('click', function() {
                        // Re-enable all response buttons
                        buttons.forEach(btn => btn.disabled = false);
                        buttons.forEach(btn => btn.classList.remove('selected-response'));
                        redoButton.remove();

                        const deleteData = {
                            'clause_id': clauseId,
                            'clause_type': clauseType
                        };

                        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

                        fetch('/delete_response', {
                            method: 'DELETE',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRFToken': csrfToken
                            },
                            body: JSON.stringify(deleteData)
                        })
                        .then(response => response.json())
                        .then(result => {
                            if (result.status === 'success') {
                                console.log('Response deleted from database');
                                answeredClauses = answeredClauses.filter(id => id !== clauseId);
                                localStorage.setItem('answeredClauses', JSON.stringify(answeredClauses));
                            } else {
                                console.error('Error deleting response:', result.message);
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                        });
                    });
                }
            }
        }
    }

    // On page load, move all answered clauses to the bottom
    answeredClauses.forEach(clauseId => {
        const clauseItem = document.querySelector(`.response-button[data-clause-id="${clauseId}"]`)?.closest('.clause-item');
        if (clauseItem) {
            moveClauseToBottom(clauseItem);
        }
    });
});
