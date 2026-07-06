#!/bin/bash

# ==============================================================================
# SCRIPT D'AUDIT DE NETTOYAGE GITHUB
# Objectif : Analyser l'état des PRs et branches par rapport à main sans modifier le code.
# ==============================================================================

# --- CONFIGURATION ---
# Ajoutez vos organisations ici, séparées par des espaces
ORGANIZATIONS=("mon-org-1" "mon-org-2") 
MAIN_BRANCH="main"
OUTPUT_FILE="audit_report.csv"

# Initialisation du fichier de rapport
echo "Organisation,Repository,PR_Number,Branch,Status,Action_Required" > "$OUTPUT_FILE"

echo "🚀 Démarrage de l'audit... Rapport généré dans $OUTPUT_FILE"

for ORG in "${ORGANIZATIONS[@]}"; do
    echo "📦 Analyse de l'organisation : $ORG"
    
    # Liste tous les repos de l'organisation (filtrage possible ici)
    REPOS=$(gh repo list "$ORG" --limit 1000 --json name -q '.[].name')

    for REPO_NAME in $REPOS; do
        REPO="$ORG/$REPO_NAME"
        echo "  📁 Repo: $REPO"

        # Cloner le repo dans un dossier temporaire pour éviter de polluer le workspace
        # On fait un clone "shallow" (profondeur 1) pour aller plus vite, 
        # mais pour l'audit on a besoin de l'historique, donc on clone normalement.
        TMP_DIR="tmp_$REPO_NAME"
        git clone "https://github.com/$REPO" "$TMP_DIR" &> /dev/null
        cd "$TMP_DIR" || continue

        # Liste des PRs ouvertes
        PRS=$(gh pr list --repo "$REPO" --state open --json number,headRefName -q '.[] | "\(.number)|\(.headRefName)"')

        if [ -z "$PRS" ]; then
            echo "    - Aucune PR ouverte."
            cd ..
            rm -rf "$TMP_DIR"
            continue
        fi

        for PR_DATA in $PRS; do
            PR_NUM=$(echo "$PR_DATA" | cut -d'|' -f1)
            BRANCH=$(echo "$PR_DATA" | cut -d'|' -f2)
            
            echo "    🔍 Analyse PR #$PR_NUM (branche: $BRANCH)..."

            # S'assurer que main est à jour
            git checkout "$MAIN_BRANCH" &> /dev/null
            git pull origin "$MAIN_BRANCH" &> /dev/null
            
            # Récupérer la branche de la PR
            git fetch origin "$BRANCH" &> /dev/null
            
            # --- ANALYSE ---
            
            # 1. Vérifier si la branche est déjà fusionnée dans main
            if git merge-base --is-ancestor "origin/$BRANCH" "origin/$MAIN_BRANCH"; then
                STATUS="Already Merged"
                ACTION="Delete Branch"
            else
                # 2. Simulation de merge pour détecter les conflits (Dry Run)
                # git merge-tree est disponible sur les versions récentes de Git (2.38+)
                # Il simule le merge sans toucher au working tree.
                MERGE_RESULT=$(git merge-tree "$MAIN_BRANCH" "origin/$BRANCH")
                
                if echo "$MERGE_RESULT" | grep -q "conflict"; then
                    STATUS="Conflict"
                    ACTION="Manual Resolve / Rebase"
                else
                    # 3. Vérifier si la branche a besoin d'un update (main a avancé)
                    if ! git merge-base --is-ancestor "origin/$MAIN_BRANCH" "origin/$BRANCH"; then
                        STATUS="Out of Date"
                        ACTION="Pull --rebase / Merge Main"
                    else
                        STATUS="Clean"
                        ACTION="Safe to Merge"
                    fi
                fi
            fi

            # Ajout au rapport CSV
            echo "$ORG,$REPO_NAME,$PR_NUM,$BRANCH,$STATUS,$ACTION" >> "../$OUTPUT_FILE"
        done

        # Nettoyage du repo temporaire
        cd ..
        rm -rf "$TMP_DIR"
    done
done

echo "✅ Audit terminé ! Consultez $OUTPUT_FILE"
